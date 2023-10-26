import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox, QFileDialog
from saes import sAes


class SAESApp(QWidget):
    def __init__(self):
        super().__init__()
        self.aes = sAes()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('S-AES 加密解密')
        self.setGeometry(800, 200, 400, 200)

        layout = QVBoxLayout()

        # 明文输入框
        self.plain_text_label = QLabel('明文(ASCII):')
        self.plain_text_input = QLineEdit()
        layout.addWidget(self.plain_text_label)
        layout.addWidget(self.plain_text_input)

        # 密文输入框
        self.cipher_text_label = QLabel('密文:')
        self.cipher_text_input = QLineEdit()
        layout.addWidget(self.cipher_text_label)
        layout.addWidget(self.cipher_text_input)

        # 密钥输入框
        self.key_label = QLabel('密钥(2字节16进制):')
        self.key_input = QLineEdit()
        layout.addWidget(self.key_label)
        layout.addWidget(self.key_input)

        # 加密按钮
        self.encrypt_button = QPushButton('加密')
        self.encrypt_button.clicked.connect(self.encrypt)
        layout.addWidget(self.encrypt_button)

        # 解密按钮
        self.decrypt_button = QPushButton('解密')
        self.decrypt_button.clicked.connect(self.decrypt)
        layout.addWidget(self.decrypt_button)

        # 清空按钮
        self.clear_button = QPushButton('清空')
        self.clear_button.clicked.connect(self.clear)
        layout.addWidget(self.clear_button)

        # 导出按钮
        self.export_button = QPushButton('导出')
        self.export_button.clicked.connect(self.export_data)
        layout.addWidget(self.export_button)

        # 结果显示
        self.result_label = QLabel('')
        layout.addWidget(self.result_label)
        self.setLayout(layout)

    def ascii_to_hex(self, string):
        hex_list = []
        length = len(string)
        if length % 2 == 1:
            string += ' '
            length += 1
        for i in range(0, length, 2):
            ascii_code = ord(string[i])
            hex_code = hex(ascii_code)[2:].zfill(2)
            hex_str = hex_code
            ascii_code = ord(string[i + 1])
            hex_code = hex(ascii_code)[2:].zfill(2)
            hex_str += hex_code
            if len(hex_str) == 4:
                hex_list.append(hex_str)
        return hex_list
    # def ascii_to_hex(self, string):
    #     hex_list = []
    #
    #     for char in string:
    #         ascii_code = ord(char)
    #         hex_code = hex(ascii_code)[2:]  # Remove the "0x" prefix
    #         hex_code = hex_code.rjust(2, '0')  # Ensure it's always 2 digits
    #
    #         pair = [int("0x" + hex_code[0], 16), int("0x" + hex_code[1], 16)]
    #         hex_list.append(pair)
    #
    #     return hex_list

    def hex_to_ascii(self, string):
        ascii_str = ''
        hex_list = [string[i:i + 2] for i in range(0, len(string), 2)]
        for hex_code in hex_list:
            ascii_code = int(hex_code, 16)
            ascii_str += chr(ascii_code)
        return ascii_str

    def encrypt(self):
        plaintext = self.plain_text_input.text()
        key = self.key_input.text()

        if plaintext == '' or key == '':
            QMessageBox.warning(self, '警告', '请输入明文和密钥')
            return

        try:
            hex_list = self.ascii_to_hex(plaintext)
            key = int(key, 16)
        except ValueError:
            QMessageBox.warning(self, '警告', '请输入正确格式的数字')
            return

        ciphertext_list = []
        for hex_str in hex_list:
            plaintext = [[int(hex_str[0], 16), int(hex_str[2], 16)],
                         [int(hex_str[1], 16), int(hex_str[3], 16)]]
            print(plaintext)
            ciphertext = self.aes.encrypt(plaintext, key)
            ciphertext_list.append(f'{ciphertext[0][0]:X}{ciphertext[1][0]:X}'
                                   f'{ciphertext[0][1]:X}{ciphertext[1][1]:X}')

        ciphertext = ''.join(ciphertext_list)
        ciphertext_ascii = self.hex_to_ascii(ciphertext)
        self.cipher_text_input.setText(ciphertext)
        self.result_label.setText(f'加密成功\n密文(16进制)：{ciphertext}\n密文（ASCII）：{ciphertext_ascii}')

    def decrypt(self):
        ciphertext = self.cipher_text_input.text()
        key = self.key_input.text()

        if ciphertext == '' or key == '':
            QMessageBox.warning(self, '警告', '请输入密文和密钥')
            return

        try:
            hex_list = []
            for i in range(0, len(ciphertext), 4):
                hex_str = ciphertext[i:i + 4]
                hex_list.append(hex_str)
            key = int(key, 16)
        except ValueError:
            QMessageBox.warning(self, '警告', '请输入正确格式的数字')
            return

        plaintext_list = []
        for hex_str in hex_list:
            ciphertext = [[int(hex_str[0], 16), int(hex_str[2], 16)],
                          [int(hex_str[1], 16), int(hex_str[3], 16)]]
            plaintext = self.aes.decrypt(ciphertext, key)
            plaintext_list.append(f'{plaintext[0][0]:X}{plaintext[1][0]:X}'
                                  f'{plaintext[0][1]:X}{plaintext[1][1]:X}')

        plaintext = ''.join(plaintext_list)
        plaintext_ascii = self.hex_to_ascii(plaintext)
        self.plain_text_input.setText(plaintext)
        self.result_label.setText(f'解密成功\n明文(16进制)：{plaintext}\n明文(ASCII)：{plaintext_ascii}')

    def export_data(self):
        plaintext = self.plain_text_input.text()
        ciphertext = self.cipher_text_input.text()
        key = self.key_input.text()
        ciphertext_ascii = self.hex_to_ascii(ciphertext)

        if plaintext == '' and ciphertext == '' and key == '':
            QMessageBox.warning(self, '警告', '没有数据可以导出')
            return

        options = QFileDialog.Options()
        options |= QFileDialog.ReadOnly
        file_name, _ = QFileDialog.getSaveFileName(self, "保存文件", "", "文本文件 (*.txt)", options=options)

        if file_name:
            with open(file_name, 'w', encoding='utf-8') as file:
                file.write(f'明文: {plaintext}\n')
                file.write(f'密钥: {key}\n')
                file.write(f'密文(16进制): {ciphertext}\n')
                file.write(f'密文(ASCII)：{ciphertext_ascii}\n')
            QMessageBox.information(self, '提示', '数据已成功导出')

    def clear(self):
        self.plain_text_input.clear()
        self.cipher_text_input.clear()
        self.key_input.clear()
        self.result_label.clear()

def main():
    app = QApplication(sys.argv)
    window = SAESApp()
    print(window.ascii_to_hex('ok'))
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()
