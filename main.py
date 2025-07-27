import sys
import os
import subprocess
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout, QComboBox, QTextEdit, QProgressBar
)
from PyQt6.QtGui import QFont, QPalette, QColor
from PyQt6.QtCore import Qt


class VideoConverter(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("All Video Format Converter")
        self.setFixedSize(400, 400)  # Adjusted size to accommodate the log display
        self.setStyleSheet("background-color: #1e1e2f; color: #ffffff;")

        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout()

        title = QLabel("🎬 All Video Format Converter")
        title.setFont(QFont("Arial", 16))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.file_label = QLabel("No file selected")
        self.file_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.file_label.setStyleSheet("padding: 10px; color: #bbbbbb;")
        layout.addWidget(self.file_label)

        browse_btn = QPushButton("📂 Browse Video File")
        browse_btn.setStyleSheet("background-color: #3366cc; color: white; padding: 10px;")
        browse_btn.clicked.connect(self.browse_file)
        layout.addWidget(browse_btn)

        self.resolution_dropdown = QComboBox()
        self.resolution_dropdown.addItems(["Original", "720p", "1080p", "4K",
                                           "1440p", "2K", "8K", "Custom"])
        self.resolution_dropdown.setStyleSheet("background-color: #444; color: white; padding: 5px;")
        layout.addWidget(self.resolution_dropdown)

        self.format_dropdown = QComboBox()
        self.format_dropdown.addItems([
    # 🟢 Most Popular & Widely Supported
    "mp4", "mkv", "mov", "avi", "wmv", "webm", "flv", "mpeg", "mpg", "m4v", "3gp",

    # 🟡 Professional/Broadcast/Editing Use
    "mxf", "avchd", "ts", "mts", "m2ts", "vob", "3gp", "3g2", "f4v", "ogv",
    "dvr-ms", "tod", "mod", "braw", "dv", "mpe", "mpv", "h264", "hevc", "264",

    # 🔵 Web & Streaming Formats
    "ogm", "ogx", "f4a", "f4b", "f4p", "qt", "rmvb", "rm", "swf", "asf",

    # 🔴 Legacy Formats
    "dat", "divx", "nsv", "yuv", "ivf", "evo", "ifo", "bin", "cpi", "rec",

    # 🟣 Rare / Niche Formats
    "bik", "smk", "dcr", "nut", "trp", "tp", "ps", "mlv", "cin", "mj2",
    "mjpeg", "mjpg", "svi", "vcd", "v210", "smv", "dirac", "m1v", "m2v", "mp2v",
    "dvx", "wtv", "xesc", "tivo", "ogv", "gxf", "lsf", "lsx", "dvsd", "dcr",
    "trm", "mve", "mxg", "avc", "film", "fvim", "wve", "sdp", "y4m", "tsp",
    "h265", "vp8", "vp9", "iso", "iso.mp4", "rpl", "mss", "mmd", "rec", "amv"])
        self.format_dropdown.setCurrentText("mp4")
        self.format_dropdown.setStyleSheet("background-color: #444; color: white; padding: 5px;")
        layout.addWidget(self.format_dropdown)

        self.convert_btn = QPushButton("🔁 Convert File")
        self.convert_btn.setStyleSheet("background-color: #28a745; color: white; padding: 10px;")
        self.convert_btn.clicked.connect(self.convert_video)
        self.convert_btn.setEnabled(False)
        layout.addWidget(self.convert_btn)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.status_label.setStyleSheet("padding: 10px;")
        layout.addWidget(self.status_label)

        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setStyleSheet("background-color: #2e2e3e; color: #ffffff; padding: 10px;")
        layout.addWidget(self.log_display)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setStyleSheet("background-color: none; color: white; padding: 5px;")
        self.progress_bar.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(self.progress_bar)

        self.setLayout(layout)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select Input File", "", "Video Files (*.*)")
        if file_path:
            self.input_file = file_path
            self.file_label.setText(f"Selected: {os.path.basename(file_path)}")

            # Ask the user for the save location
            selected_format = self.format_dropdown.currentText()
            save_path, _ = QFileDialog.getSaveFileName(
                self, "Save File As", os.path.splitext(file_path)[0] + f".{selected_format}", f"{selected_format.upper()} Files (*.{selected_format})"
            )

            if save_path:
                self.output_file = save_path
                self.convert_btn.setEnabled(True)
            else:
                self.file_label.setText("Save location not selected.")
                self.convert_btn.setEnabled(False)

    def convert_video(self):
        self.status_label.setText("⏳ Conversion started. Please wait...")
        self.progress_bar.setValue(0)
        QApplication.processEvents()

        resolution = self.resolution_dropdown.currentText()
        scale_filter = None

        if resolution == "720p":
            scale_filter = "scale=-1:720"
        elif resolution == "1080p":
            scale_filter = "scale=-1:1080"
        elif resolution == "4K":
            scale_filter = "scale=-1:2160"

        ffmpeg_dir = os.path.join(os.getcwd(), 'ffmpeg')
        ffmpeg_path = os.path.join(ffmpeg_dir, 'ffmpeg.exe')

        try:
            if not os.path.exists(ffmpeg_path):
                self.log_display.append("[INFO] ffmpeg executable not found in local directory. Falling back to system PATH.")
                ffmpeg_path = "ffmpeg"

            if subprocess.run([ffmpeg_path, "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode != 0:
                raise FileNotFoundError("ffmpeg executable not found or not accessible.")

            self.log_display.append("[INFO] ffmpeg is accessible. Starting conversion...")

            # Get video duration
            probe_command = [ffmpeg_path, "-i", self.input_file, "-hide_banner"]
            probe_process = subprocess.run(probe_command, stderr=subprocess.PIPE, text=True)
            duration_line = next((line for line in probe_process.stderr.splitlines() if "Duration" in line), None)
            if duration_line:
                try:
                    duration_parts = duration_line.split(",")[0].split(" ")[-1].split(":")
                    total_duration = int(duration_parts[0]) * 3600 + int(duration_parts[1]) * 60 + float(duration_parts[2])
                    self.log_display.append(f"[INFO] Video duration: {total_duration} seconds.")
                except (ValueError, IndexError) as e:
                    total_duration = None
                    self.log_display.append(f"[WARNING] Unable to parse video duration. Progress bar may not work correctly. Error: {str(e)}")
            else:
                total_duration = None
                self.log_display.append("[WARNING] Duration information not found in ffmpeg output. Progress bar may not work correctly.")

            selected_format = self.format_dropdown.currentText()
            command = [
                ffmpeg_path,
                "-i", self.input_file,
            ]

            if scale_filter:
                command.extend(["-vf", scale_filter])
                self.log_display.append(f"[INFO] Applying resolution filter: {scale_filter}")

            # Dynamically handle output format without hardcoding
            command.extend(["-c:v", "libx264", "-preset", "fast", "-c:a", "aac", "-b:a", "192k"])

            command.append(self.output_file)

            process = subprocess.Popen(
                command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
            )

            for line in process.stdout:
                self.log_display.append(f"[LOG] {line.strip()}\n")
                QApplication.processEvents()

                if total_duration and "time=" in line:
                    time_str = next((part.split("=")[1] for part in line.split() if part.startswith("time=")), None)
                    if time_str:
                        time_parts = time_str.split(":")
                        elapsed_time = int(time_parts[0]) * 3600 + int(time_parts[1]) * 60 + float(time_parts[2])
                        progress = int((elapsed_time / total_duration) * 100)
                        self.progress_bar.setValue(progress)

            process.wait()

            if process.returncode == 0:
                self.status_label.setText("✅ Conversion completed successfully!")
                self.progress_bar.setValue(100)
                self.log_display.append("[SUCCESS] Conversion completed successfully.")
            else:
                self.status_label.setText("❌ Conversion failed. Please check the logs.")
                self.log_display.append("[ERROR] Conversion failed. Check the logs for details.")

        except FileNotFoundError as e:
            self.status_label.setText(f"❌ Error: ffmpeg executable not found. {str(e)}")
            self.log_display.append(f"[ERROR] ffmpeg executable not found: {str(e)}")
        except Exception as e:
            self.status_label.setText(f"❌ Unexpected error: {str(e)}")
            self.log_display.append(f"[ERROR] Unexpected error: {str(e)}")


def check_and_download_ffmpeg():
    ffmpeg_dir = os.path.join(os.getcwd(), 'ffmpeg')
    ffmpeg_path = os.path.join(ffmpeg_dir, 'ffmpeg.exe')

    # Check if ffmpeg executable exists in the local directory or system PATH
    if os.path.exists(ffmpeg_path):
        print("ffmpeg is available in the local directory.")
    elif subprocess.run(["ffmpeg", "-version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE).returncode == 0:
        print("ffmpeg is available in the system PATH.")
    else:
        print("Error: ffmpeg executable not found. Please install ffmpeg and ensure it is accessible.")
        sys.exit(1)


if __name__ == "__main__":
    check_and_download_ffmpeg()
    app = QApplication(sys.argv)
    window = VideoConverter()
    window.show()
    sys.exit(app.exec())
