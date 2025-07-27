# Video Converter

A Python-based video conversion tool that uses FFmpeg for format conversion and processing.

## Features
- Convert video files between different formats
- Uses FFmpeg for efficient video processing
- Simple command-line interface
- Batch processing support
- Progress tracking
- Error handling and logging

## Requirements
- Python 3.8 or higher
- FFmpeg (must be installed and added to system PATH)
- PyInstaller (for packaging)

## Installation

### Prerequisites
1. Install Python 3.8 or higher from [python.org](https://www.python.org/downloads/)
   - During installation, ensure "Add Python to PATH" is checked

2. Install FFmpeg:
   - Windows: Download and install from [FFmpeg official site](https://ffmpeg.org/download.html)
   - Linux: Install using package manager
   - macOS: Install using Homebrew (`brew install ffmpeg`)

### Installation Steps
1. Clone the repository:
```bash
git clone https://github.com/laravelgpt/video-converter.git
cd video-converter
```

2. Install Python dependencies:
```bash
pip install -r requirements.txt
```

3. Verify installation:
```bash
python --version  # Should show Python 3.8 or higher
ffmpeg -version   # Should show FFmpeg version
```

## Usage

### Basic Usage
```bash
python main.py -i input.mp4 -o output.mp4
```

### Supported Formats
- Input: MP4, AVI, MOV, MKV, WMV, FLV, M4V, 3GP
- Output: MP4, AVI, MOV, MKV, WMV, FLV, M4V, 3GP

### Command Line Options
```bash
# Show help and usage information
python main.py -h

# Convert single file with specific format
python main.py -i input.mp4 -o output.mp4 -f mp4

# Convert with custom resolution
python main.py -i input.mp4 -o output.mp4 -r 1920x1080

# Convert with custom bitrate
python main.py -i input.mp4 -o output.mp4 -b 5000k

# Batch convert folder
python main.py --batch --input-folder input_folder/ --output-folder output_folder/

# Convert with progress tracking
python main.py -i input.mp4 -o output.mp4 --progress
```

### Advanced Options
```bash
# Set video codec
python main.py -i input.mp4 -o output.mp4 --video-codec h264

# Set audio codec
python main.py -i input.mp4 -o output.mp4 --audio-codec aac

# Set frame rate
python main.py -i input.mp4 -o output.mp4 --fps 30

# Set audio bitrate
python main.py -i input.mp4 -o output.mp4 --audio-bitrate 192k

# Set preset (ultrafast, superfast, veryfast, faster, fast, medium, slow, slower, veryslow)
python main.py -i input.mp4 -o output.mp4 --preset medium
```

### Example Usage
1. Basic conversion:
```bash
python main.py -i input.mp4 -o output.mp4
```

2. Convert with specific format and resolution:
```bash
python main.py -i input.mp4 -o output.mp4 -f avi -r 1280x720
```

3. Convert with custom settings:
```bash
python main.py -i input.mp4 -o output.mp4 -f mp4 -r 1920x1080 -b 8000k --video-codec h264 --audio-codec aac
```

4. Batch convert folder with progress tracking:
```bash
python main.py --batch --input-folder input_folder/ --output-folder output_folder/ --progress
```

5. Convert with audio normalization:
```bash
python main.py -i input.mp4 -o output.mp4 --normalize-audio
```

### Troubleshooting
1. If FFmpeg is not found:
   - Ensure FFmpeg is installed and added to PATH
   - Verify FFmpeg installation: `ffmpeg -version`

2. If conversion fails:
   - Check input file format is supported
   - Verify sufficient disk space
   - Check for permission issues

3. If progress tracking is not working:
   - Ensure terminal supports ANSI escape codes
   - Try running without progress tracking option

### Tips
- Use `-h` or `--help` for complete option list
- For best quality, use higher bitrates and appropriate presets
- Batch conversion is faster with multiple CPU cores
- Use progress tracking for long conversions
- Always verify output files after conversion

## Contributing
1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License
MIT License
