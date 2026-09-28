//! Grabs the primary monitor and encodes it to an H.264 Annex-B bitstream,
//! frame by frame, for the WebRTC video track.
//!
//! This is the proof-of-concept path: full-frame grab, software encode via
//! OpenH264. Production would use the OS duplication API for damage rectangles
//! and a hardware encoder. Kept deliberately simple and CPU-bounded by the
//! frame interval the caller ticks at.

use anyhow::{Context, Result};
use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate, IntraFramePeriod, UsageType};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use xcap::Monitor;

/// Encode ceiling. Browsers negotiate H.264 level ~3.1 (about 720p); sending a
/// full 1080p+ desktop at a higher level makes their decoder drop every frame
/// (black video). Downscaling to fit keeps decoding reliable and cuts bandwidth.
/// Control is unaffected: the mouse maps to the full monitor, not this size.
const MAX_ENCODE_W: u32 = 1280;
const MAX_ENCODE_H: u32 = 720;

pub struct ScreenSource {
    monitor: Monitor,
    encoder: Encoder,
    width: u32,
    height: u32,
}

/// The largest even width/height that fits `(w, h)` within `(mw, mh)` keeping
/// aspect ratio. H.264 needs even dimensions.
fn fit_within(w: u32, h: u32, mw: u32, mh: u32) -> (u32, u32) {
    let (nw, nh) = if w <= mw && h <= mh {
        (w, h)
    } else {
        let scale = (mw as f64 / w as f64).min(mh as f64 / h as f64);
        (
            ((w as f64 * scale).round() as u32).max(2),
            ((h as f64 * scale).round() as u32).max(2),
        )
    };
    (nw & !1, nh & !1)
}

impl ScreenSource {
    /// Opens the primary monitor and an encoder tuned for screen content.
    pub fn primary(fps: f32, kbps: u32) -> Result<Self> {
        let monitors = Monitor::all().context("enumerating monitors")?;
        let monitor = monitors
            .into_iter()
            .find(|m| m.is_primary().unwrap_or(false))
            .context("no primary monitor")?;
        let width = monitor.width()?;
        let height = monitor.height()?;

        let config = EncoderConfig::new()
            .usage_type(UsageType::ScreenContentRealTime)
            .max_frame_rate(FrameRate::from_hz(fps))
            .bitrate(BitRate::from_bps(kbps * 1000))
            // Emit a keyframe about every 2s so a browser that joins (or briefly
            // loses packets) can start decoding quickly instead of showing black
            // until the next scene change.
            .intra_frame_period(IntraFramePeriod::from_num_frames((fps.max(1.0) * 2.0) as u32));
        // `Encoder::new()` also works (source-built API); with_api_config lets
        // us pass the screen-content tuning above.
        let encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)
            .context("initialising H.264 encoder")?;

        Ok(Self {
            monitor,
            encoder,
            width,
            height,
        })
    }

    pub fn dimensions(&self) -> (u32, u32) {
        (self.width, self.height)
    }

    /// Captures one frame and returns its H.264 NAL units (Annex-B).
    /// Returns `Ok(None)` when the encoder emitted nothing this frame.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>> {
        let image = self.monitor.capture_image().context("capturing screen")?;
        let (cw, ch) = (image.width(), image.height());
        let (tw, th) = fit_within(cw, ch, MAX_ENCODE_W, MAX_ENCODE_H);

        // Resize only when needed (or when the raw size is odd — H.264 needs even).
        let resized;
        let src = if (tw, th) != (cw, ch) {
            resized = image::imageops::resize(&image, tw, th, image::imageops::FilterType::Triangle);
            &resized
        } else {
            &image
        };

        let (w, h) = (src.width() as usize, src.height() as usize);
        let rgba = RgbaSliceU8::new(src.as_raw(), (w, h));
        let yuv = YUVBuffer::from_rgb_source(rgba);
        let bitstream = self.encoder.encode(&yuv).context("encoding frame")?;
        let data = bitstream.to_vec();
        Ok((!data.is_empty()).then_some(data))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encodes a synthetic frame with no screen involved. This is the runtime
    /// check that OpenH264's C++ (compiled from source, assembled with NASM)
    /// actually built and works on this platform — `cargo test` in CI exercises
    /// it, so a broken native toolchain fails loudly rather than at deploy time.
    #[test]
    fn openh264_encodes_a_synthetic_frame() {
        let (w, h) = (320usize, 240usize);
        let rgba = vec![0x80u8; w * h * 4]; // mid-grey RGBA
        let config = EncoderConfig::new().usage_type(UsageType::ScreenContentRealTime);
        let mut encoder = Encoder::with_api_config(openh264::OpenH264API::from_source(), config)
            .expect("encoder init");
        let yuv = YUVBuffer::from_rgb_source(RgbaSliceU8::new(&rgba, (w, h)));
        let bitstream = encoder.encode(&yuv).expect("encode");
        // The first frame is a keyframe carrying SPS/PPS, so it is never empty.
        assert!(
            !bitstream.to_vec().is_empty(),
            "expected a non-empty keyframe"
        );
    }
}
