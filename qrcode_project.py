import sys
import hashlib
import qrcode
import os
import socket
import psutil # Import psutil

from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QLineEdit, QLabel, QFileDialog,
    QCheckBox, QGroupBox, QMessageBox, QScrollArea, QFrame, QSizePolicy,
    QProgressBar, QComboBox
)
from PyQt5.QtGui import QPixmap, QImage, QDragEnterEvent, QDropEvent, QCursor
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QUrl, QSize

# --- Hàm trợ giúp để lấy địa chỉ IP thực của máy (không cần Internet) ---
def get_local_ip_address_no_internet():
    """
    Attempts to get the non-loopback IP address of the machine without requiring internet access.
    Iterates through network interfaces using psutil.
    """
    try:
        addresses = psutil.net_if_addrs()
        for interface_name, interface_addresses in addresses.items():
            for addr in interface_addresses:
                # Check for IPv4 address and ensure it's not a loopback address
                if addr.family == socket.AF_INET and not addr.address.startswith('127.'):
                    return addr.address
        return "127.0.0.1" # Fallback if no non-loopback IP found
    except Exception as e:
        # Fallback in case psutil is not installed or other errors
        print(f"Error getting local IP with psutil: {e}")
        return "127.0.0.1"

# --- Phần 1: Logic xử lý Hash và QR (chạy trong một thread riêng để tránh treo GUI) ---
class HashQrWorker(QThread):
    # Tín hiệu để cập nhật GUI
    hash_calculated = pyqtSignal(str, str) # (hash_value, hash_algorithm)
    qr_generated = pyqtSignal(str, str) # (platform_name, qr_filepath)
    error_occurred = pyqtSignal(str)
    work_finished = pyqtSignal() # Tín hiệu báo hiệu công việc đã hoàn thành
    progress_updated = pyqtSignal(int) # Tín hiệu cập nhật tiến trình
    status_updated = pyqtSignal(str) # Tín hiệu cập nhật trạng thái

    def __init__(self, file_path, selected_platforms, selected_hash_algos, qr_size_factor):
        super().__init__()
        self.file_path = file_path
        self.selected_platforms = selected_platforms
        self.selected_hash_algos = selected_hash_algos
        self.qr_size_factor = qr_size_factor
        self.platforms = {
            "VirusTotal": "https://www.virustotal.com/gui/file/{hash}/detection",
            "Hybrid Analysis": "https://hybrid-analysis.com/search?query={hash}",
            "AnyRun": "https://any.run/submissions?search={hash}",
            "AlienVault OTX": "https://otx.alienvault.com/indicator/file/{hash}",
            "Triage": "https://tria.ge/s?q={hash}",
            # Bạn có thể thêm các nền tảng khác vào đây.
            # Cần kiểm tra xem nền tảng đó chấp nhận loại hash nào (MD5, SHA1, SHA256) cho URL tìm kiếm của họ.
        }
        self.hashes = {} # Lưu trữ các hash đã tính toán

    def run(self):
        try:
            self.status_updated.emit("Đang tính toán hash...")
            self.progress_updated.emit(0)

            # Lấy hostname và IP address thực tế (không cần internet)
            try:
                hostname = socket.gethostname()
                ip_address = get_local_ip_address_no_internet() # Sử dụng hàm mới để lấy IP
                # Thay thế các ký tự không hợp lệ trong tên thư mục
                hostname_safe = hostname.replace('.', '_').replace('-', '_').replace(' ', '_')
                ip_address_safe = ip_address.replace('.', '_')
                machine_info = f"{hostname_safe}_{ip_address_safe}"
            except Exception as e:
                machine_info = "unknown_machine_unknown_ip" # Fallback nếu không lấy được thông tin
                self.status_updated.emit(f"Cảnh báo: Không thể lấy hostname/IP. Thư mục sẽ dùng tên mặc định. Lỗi: {e}")


            # 1. Tính toán các Hash được chọn
            for algo in self.selected_hash_algos:
                file_hash = self._get_file_hash(self.file_path, algo)
                if not file_hash:
                    self.error_occurred.emit(f"Không thể tính toán hash {algo} của tệp.")
                    self.work_finished.emit()
                    return
                self.hashes[algo] = file_hash
                self.hash_calculated.emit(file_hash, algo)

            total_qrs = len(self.selected_platforms) * len(self.selected_hash_algos)
            if total_qrs == 0:
                self.status_updated.emit("Không có QR nào được tạo.")
                self.work_finished.emit()
                return

            qr_count = 0
            # Cập nhật tên thư mục đầu ra với hostname và IP
            file_basename_sanitized = os.path.basename(self.file_path).replace('.', '_').replace(' ', '_')
            output_base_dir = os.path.join(os.getcwd(), f"qrcodes_{file_basename_sanitized}_{machine_info}")

            if not os.path.exists(output_base_dir):
                os.makedirs(output_base_dir)

            # 2. Tạo QR Code cho các nền tảng và các hash đã chọn
            for platform_name in self.selected_platforms:
                if platform_name not in self.platforms:
                    self.error_occurred.emit(f"Nền tảng '{platform_name}' không được hỗ trợ.")
                    continue

                for hash_algo, file_hash in self.hashes.items():
                    self.status_updated.emit(f"Đang tạo QR cho {platform_name} ({hash_algo})...")
                    output_dir = os.path.join(output_base_dir, hash_algo.upper())
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)

                    url_template = self.platforms[platform_name]
                    if self._create_qr_for_platform(file_hash, platform_name, hash_algo, url_template, output_dir, self.qr_size_factor):
                        qr_count += 1
                    self.progress_updated.emit(int((qr_count / total_qrs) * 100))

            self.status_updated.emit(f"Hoàn tất! Đã tạo {qr_count} mã QR.")

        except Exception as e:
            self.error_occurred.emit(f"Đã xảy ra lỗi không mong muốn: {e}")
        finally:
            self.progress_updated.emit(100)
            self.work_finished.emit()

    def _get_file_hash(self, filepath, hash_algorithm):
        """Tính toán hash của một tệp."""
        hasher = hashlib.new(hash_algorithm)
        try:
            with open(filepath, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except FileNotFoundError:
            return None
        except Exception as e:
            self.error_occurred.emit(f"Lỗi khi tính toán hash {hash_algorithm}: {e}")
            return None

    def _create_qr_for_platform(self, file_hash, platform_name, hash_algo, url_template, output_dir, qr_size_factor):
        """Tạo mã QR cho một nền tảng cụ thể."""
        if not file_hash:
            return False

        # Các cảnh báo về loại hash mà nền tảng ưu tiên/chấp nhận
        if platform_name in ["VirusTotal", "Triage", "AnyRun", "Hybrid Analysis", "AlienVault OTX"] and hash_algo not in ["sha256", "md5", "sha1"]:
            self.status_updated.emit(f"Cảnh báo: {platform_name} ưu tiên SHA256, MD5, SHA1 cho tìm kiếm. {hash_algo} có thể không hoạt động tốt.")


        search_url = url_template.replace('{hash}', file_hash)
        try:
            box_size = 7 + (qr_size_factor * 5)

            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=box_size,
                border=4,
            )
            qr.add_data(search_url)
            qr.make(fit=True)

            img = qr.make_image(fill_color="black", back_color="white")
            filename = os.path.join(output_dir, f"{platform_name}_{hash_algo}_{file_hash[:8]}.png")
            img.save(filename)
            self.qr_generated.emit(platform_name, filename)
            return True
        except Exception as e:
            self.error_occurred.emit(f"Lỗi khi tạo QR cho {platform_name} ({hash_algo}): {e}")
            return False

# --- Phần 2: Giao diện PyQt5 ---
class HashQrApp(QWidget):
    def __init__(self):
        super().__init__()
        self.current_file_path = ""
        self.worker_thread = None
        self.initUI()
        self.setAcceptDrops(True)

    def initUI(self):
        self.setWindowTitle('Công cụ Tạo QR Hash File (OT Safe)')
        self.setGeometry(100, 100, 1200, 750)

        main_h_layout = QHBoxLayout()

        # --- Cột trái: Các tùy chọn và điều khiển ---
        left_column_layout = QVBoxLayout()
        left_column_layout.setContentsMargins(10, 10, 10, 10)
        left_column_layout.setSpacing(15)

        # Phần 1: Chọn tệp (kéo thả)
        file_group = QGroupBox("1. Kéo & Thả tệp vào đây, hoặc Duyệt")
        file_layout = QVBoxLayout()
        self.file_path_label = QLineEdit("Kéo tệp vào đây, hoặc nhấn 'Duyệt...'")
        self.file_path_label.setReadOnly(True)
        self.file_path_label.setAlignment(Qt.AlignCenter)
        self.file_path_label.setStyleSheet("border: 2px dashed #aaa; padding: 10px; background-color: #f0f0f0; border-radius: 5px;")
        self.file_path_label.setMinimumHeight(60)

        browse_button_layout = QHBoxLayout()
        browse_button_layout.addStretch(1)
        self_browse_button = QPushButton("Duyệt...")
        self_browse_button.clicked.connect(self.browse_file)
        self_browse_button.setFixedSize(120, 35)
        self_browse_button.setStyleSheet("QPushButton { background-color: #007bff; color: white; border-radius: 5px; font-weight: bold; } QPushButton:hover { background-color: #0056b3; }")
        browse_button_layout.addWidget(self_browse_button)
        browse_button_layout.addStretch(1)

        file_layout.addWidget(self.file_path_label)
        file_layout.addLayout(browse_button_layout)
        file_group.setLayout(file_layout)
        left_column_layout.addWidget(file_group)

        # Phần 2: Hash của Tệp & Tùy chọn Hash
        hash_options_group = QGroupBox("2. Hash của Tệp & Tùy chọn")
        hash_options_layout = QVBoxLayout()

        self.hash_display_label = QLabel("Hash sẽ xuất hiện ở đây sau khi chọn tệp.")
        self.hash_display_label.setWordWrap(True)
        self.hash_display_label.setTextInteractionFlags(Qt.TextSelectableByMouse | Qt.TextSelectableByKeyboard)
        hash_options_layout.addWidget(self.hash_display_label)

        hash_algo_layout = QHBoxLayout()
        hash_algo_layout.addWidget(QLabel("Chọn thuật toán Hash:"))
        self.hash_algo_checkboxes = {}
        hash_algos = ["SHA256", "MD5", "SHA1", "SHA512"]
        for algo in hash_algos:
            chk_box = QCheckBox(algo)
            if algo == "SHA256":
                chk_box.setChecked(True)
            self.hash_algo_checkboxes[algo] = chk_box
            hash_algo_layout.addWidget(chk_box)
        hash_algo_layout.addStretch(1)
        hash_options_layout.addLayout(hash_algo_layout)
        hash_options_group.setLayout(hash_options_layout)
        left_column_layout.addWidget(hash_options_group)

        # Phần 3: Chọn Nền tảng Tạo QR & Tùy chỉnh
        qr_options_group = QGroupBox("3. Chọn Nền tảng Tạo QR & Tùy chỉnh")
        qr_options_layout = QVBoxLayout()

        platform_layout = QVBoxLayout()
        self.platform_checkboxes = {}
        # Danh sách các nền tảng sẽ hiển thị trên GUI
        common_platforms = [
            "VirusTotal", "Hybrid Analysis", "AnyRun", "AlienVault OTX", "Triage"
        ]
        for platform_name in common_platforms:
            chk_box = QCheckBox(platform_name)
            chk_box.setChecked(True)
            self.platform_checkboxes[platform_name] = chk_box
            platform_layout.addWidget(chk_box)

        select_all_btn_layout = QHBoxLayout()
        select_all_btn = QPushButton("Chọn Tất cả")
        select_all_btn.clicked.connect(lambda: self.set_platform_checkboxes_state(True))
        deselect_all_btn = QPushButton("Bỏ Chọn Tất cả")
        deselect_all_btn.clicked.connect(lambda: self.set_platform_checkboxes_state(False))
        select_all_btn_layout.addWidget(select_all_btn)
        select_all_btn_layout.addWidget(deselect_all_btn)
        platform_layout.addLayout(select_all_btn_layout)
        qr_options_layout.addLayout(platform_layout)

        qr_size_layout = QHBoxLayout()
        qr_size_layout.addWidget(QLabel("Kích thước QR:"))
        self.qr_size_combo = QComboBox()
        self.qr_size_combo.addItems(["Nhỏ", "Trung bình", "Lớn"])
        self.qr_size_combo.setCurrentIndex(1)
        qr_size_layout.addWidget(self.qr_size_combo)
        qr_size_layout.addStretch(1)
        qr_options_layout.addLayout(qr_size_layout)

        qr_options_group.setLayout(qr_options_layout)
        left_column_layout.addWidget(qr_options_group)

        # Nút tạo QR
        self.generate_qr_button = QPushButton("Tạo Mã QR")
        self.generate_qr_button.setFont(self.generate_qr_button.font())
        self.generate_qr_button.setStyleSheet("font-size: 18px; padding: 15px; background-color: #007bff; color: white; font-weight: bold; border-radius: 8px;")
        self.generate_qr_button.clicked.connect(self.start_qr_generation)
        self.generate_qr_button.setEnabled(False)
        left_column_layout.addWidget(self.generate_qr_button)

        # Thanh tiến trình và trạng thái
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setAlignment(Qt.AlignCenter)
        self.progress_bar.setFormat("%p%")
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setValue(0)
        left_column_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("Chờ bạn chọn tệp...")
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet("font-style: italic; color: #555; margin-top: 5px;")
        left_column_layout.addWidget(self.status_label)

        left_column_layout.addStretch(1)
        main_h_layout.addLayout(left_column_layout, 2)

        # --- Cột phải: Hiển thị QR ---
        qr_display_group = QGroupBox("Mã QR đã tạo (quét bằng điện thoại)")
        qr_display_layout = QVBoxLayout()
        self.qr_scroll_area = QScrollArea()
        self.qr_scroll_area.setWidgetResizable(True)
        self.qr_content_widget = QWidget()
        self.qr_content_layout = QVBoxLayout(self.qr_content_widget)
        self.qr_content_layout.setAlignment(Qt.AlignHCenter | Qt.AlignTop)
        self.qr_scroll_area.setWidget(self.qr_content_widget)
        qr_display_layout.addWidget(self.qr_scroll_area)
        qr_display_group.setLayout(qr_display_layout)
        main_h_layout.addWidget(qr_display_group, 3)

        self.setLayout(main_h_layout)

    # --- Phương thức xử lý kéo thả ---
    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            if len(event.mimeData().urls()) == 1 and event.mimeData().urls()[0].isLocalFile():
                event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event: QDropEvent):
        if event.mimeData().hasUrls():
            file_path = event.mimeData().urls()[0].toLocalFile()
            if os.path.isfile(file_path):
                self.process_selected_file(file_path)
            else:
                QMessageBox.warning(self, "Lỗi Kéo Thả", "Vui lòng kéo thả một TỆP hợp lệ.")
        event.acceptProposedAction()

    def set_platform_checkboxes_state(self, checked):
        for chk_box in self.platform_checkboxes.values():
            chk_box.setChecked(checked)

    def browse_file(self):
        options = QFileDialog.Options()
        file_name, _ = QFileDialog.getOpenFileName(self, "Chọn Tệp", "", "Tất cả Tệp (*);;", options=options)
        if file_name:
            self.process_selected_file(file_name)

    def process_selected_file(self, file_path):
        self.current_file_path = file_path
        self.file_path_label.setText(f"Tệp đã chọn: {os.path.basename(file_path)}")
        self.generate_qr_button.setEnabled(True)
        self.hash_display_label.setText("Đang chờ tính toán hash...")
        self.clear_qr_display()
        self.progress_bar.setValue(0)
        self.status_label.setText("Sẵn sàng tạo QR.")

        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.quit()
            self.worker_thread.wait()

        temp_hash_algos = ["SHA256"]
        self.worker_thread = HashQrWorker(self.current_file_path, [], temp_hash_algos, 0)
        self.worker_thread.hash_calculated.connect(self.update_hash_display_on_file_select)
        self.worker_thread.error_occurred.connect(self.show_error_message)
        self.worker_thread.work_finished.connect(self.on_initial_hash_finished)
        self.worker_thread.start()

    def update_hash_display_on_file_select(self, hash_value, hash_algo):
        if hash_algo == "SHA256":
            self.hash_display_label.setText(f"Hash SHA256: {hash_value}")

    def on_initial_hash_finished(self):
        self.status_label.setText("Đã tính hash ban đầu. Sẵn sàng tạo QR.")


    def start_qr_generation(self):
        if not self.current_file_path:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn một tệp trước.")
            return

        selected_platforms = [name for name, chk_box in self.platform_checkboxes.items() if chk_box.isChecked()]
        if not selected_platforms:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn ít nhất một nền tảng để tạo QR.")
            return

        selected_hash_algos = [algo.lower() for algo, chk_box in self.hash_algo_checkboxes.items() if chk_box.isChecked()]
        if not selected_hash_algos:
            QMessageBox.warning(self, "Lỗi", "Vui lòng chọn ít nhất một thuật toán hash.")
            return

        qr_size_factor = self.qr_size_combo.currentIndex()

        self.clear_qr_display()
        self.progress_bar.setValue(0)
        self.status_label.setText("Đang bắt đầu tạo QR...")

        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.quit()
            self.worker_thread.wait()

        self.generate_qr_button.setEnabled(False)

        self.worker_thread = HashQrWorker(self.current_file_path, selected_platforms, selected_hash_algos, qr_size_factor)
        self.worker_thread.hash_calculated.connect(self.update_hash_display_on_qr_gen)
        self.worker_thread.qr_generated.connect(self.add_qr_to_display)
        self.worker_thread.error_occurred.connect(self.show_error_message)
        self.worker_thread.progress_updated.connect(self.progress_bar.setValue)
        self.worker_thread.status_updated.connect(self.status_label.setText)
        self.worker_thread.work_finished.connect(self.on_qr_generation_finished)
        self.worker_thread.start()

    def update_hash_display_on_qr_gen(self, hash_value, hash_algo):
        current_text = self.hash_display_label.text()
        if "Hash SHA256:" in current_text and len(self.hash_algo_checkboxes) > 1 and hash_algo.lower() != "sha256":
            self.hash_display_label.setText(f"Hash {hash_algo.upper()}: {hash_value}\n")
        else:
            lines = current_text.split('\n')
            new_lines = []
            found = False
            for line in lines:
                if f"Hash {hash_algo.upper()}:" in line:
                    new_lines.append(f"Hash {hash_algo.upper()}: {hash_value}")
                    found = True
                else:
                    if line.strip():
                        new_lines.append(line)
            if not found:
                new_lines.append(f"Hash {hash_algo.upper()}: {hash_value}")
            self.hash_display_label.setText('\n'.join([line for line in new_lines if line.strip()]).strip())

    def add_qr_to_display(self, platform_name, qr_filepath):
        qr_container_widget = QWidget()
        qr_container_layout = QVBoxLayout(qr_container_widget)
        qr_container_layout.setAlignment(Qt.AlignCenter)

        file_basename = os.path.basename(qr_filepath)
        parts = file_basename.split('_')
        if len(parts) >= 2:
            display_name = f"{parts[0]} ({parts[1].upper()}):"
        else:
            display_name = f"{platform_name}:"

        qr_label = QLabel(display_name)
        qr_label.setAlignment(Qt.AlignCenter)
        qr_container_layout.addWidget(qr_label)

        pixmap = QPixmap(qr_filepath)
        if pixmap.isNull():
            print(f"Không thể tải hình ảnh QR từ {qr_filepath}")
            return

        qr_image_label = QLabel()
        qr_image_label.setPixmap(pixmap.scaled(250, 250, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        qr_image_label.setAlignment(Qt.AlignCenter)
        qr_container_layout.addWidget(qr_image_label)

        file_path_qr_label = QLabel(f"Đã lưu: {file_basename}")
        file_path_qr_label.setAlignment(Qt.AlignCenter)
        file_path_qr_label.setStyleSheet("font-size: 10px; color: gray;")
        qr_container_layout.addWidget(file_path_qr_label)

        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setFrameShadow(QFrame.Sunken)
        qr_container_layout.addWidget(line)

        self.qr_content_layout.addWidget(qr_container_widget)

    def clear_qr_display(self):
        while self.qr_content_layout.count():
            item = self.qr_content_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

    def clear_layout(self, layout):
        while layout.count():
            item = layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
            elif item.layout():
                self.clear_layout(item.layout())

    def show_error_message(self, message):
        QMessageBox.critical(self, "Lỗi", message)

    def on_qr_generation_finished(self):
        self.generate_qr_button.setEnabled(True)
        self.status_label.setText("Hoàn tất! Sẵn sàng tạo QR mới.")

    def reset_cursor(self):
        QApplication.restoreOverrideCursor()

    def closeEvent(self, event):
        if self.worker_thread and self.worker_thread.isRunning():
            self.worker_thread.quit()
            self.worker_thread.wait()
        event.accept()

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = HashQrApp()
    ex.show()
    sys.exit(app.exec_())