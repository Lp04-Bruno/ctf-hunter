use std::io::{IoSlice, Write as _};

fn main() -> std::io::Result<()> {
    let iterations = std::env::args()
        .nth(1)
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidInput, error))?
        .unwrap_or(10_000);
    let left = [b'A'; 64];
    let right = [b'B'; 64];
    let stdout = std::io::stdout();
    let mut output = stdout.lock();
    for _ in 0..iterations {
        let mut vectors = [IoSlice::new(&left), IoSlice::new(&right)];
        let mut remaining = &mut vectors[..];
        while !remaining.is_empty() {
            let written = output.write_vectored(remaining)?;
            if written == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "failed to write stress payload",
                ));
            }
            IoSlice::advance_slices(&mut remaining, written);
        }
    }
    output.flush()
}
