//! Grabs the primary monitor and encodes it to an H.264 Annex-B bitstream,
//! frame by frame, for the WebRTC video track.
//!
//! This is the proof-of-concept path: full-frame grab, software encode via
//! OpenH264. Production would use the OS duplication API for damage rectangles
//! and a hardware encoder. Kept deliberately simple and CPU-bounded by the
//! frame interval the caller ticks at.

use anyhow::{Context, Result};
use openh264::encoder::{BitRate, Encoder, EncoderConfig, FrameRate, UsageType};
use openh264::formats::{RgbaSliceU8, YUVBuffer};
use xcap::Monitor;

pub struct ScreenSource {
    monitor: Monitor,
    encoder: Encoder,
    width: u32,
    height: u32,
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
            .bitrate(BitRate::from_bps(kbps * 1000));
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
        let (w, h) = (image.width() as usize, image.height() as usize);
        let rgba = RgbaSliceU8::new(image.as_raw(), (w, h));
        let yuv = YUVBuffer::from_rgb_source(rgba);
        let bitstream = self.encoder.encode(&yuv).context("encoding frame")?;
        let data = bitstream.to_vec();
        Ok((!data.is_empty()).then_some(data))
    }
}
