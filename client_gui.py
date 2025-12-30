"""
远程控制软件 - 控制端（GUI版本）
使用PyQt5创建的图形界面客户端
"""
import sys
import socket
import struct
import io
import threading
import time
import getpass
from datetime import datetime
import os
import re

try:
    from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                                 QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                                 QTextEdit, QDialog, QMessageBox, QInputDialog,
                                 QTabWidget)
    from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QObject
    from PyQt5.QtGui import QImage, QPixmap, QFont, QTextCharFormat, QColor
    PYQT_AVAILABLE = True
except ImportError:
    PYQT_AVAILABLE = False
    print("[!] 警告: 未安装PyQt5，GUI功能不可用")
    print("[!] 请运行: pip install PyQt5")

try:
    from PIL import Image
    IMAGE_AVAILABLE = True
except ImportError:
    IMAGE_AVAILABLE = False
    print("[!] 警告: 未安装PIL库，画面显示功能受限")

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.backends import default_backend
    import base64
    ENCRYPTION_AVAILABLE = True
except ImportError:
    ENCRYPTION_AVAILABLE = False
    print("[!] 警告: 未安装加密库，传输加密功能不可用")


class ConnectionDialog(QDialog):
    """连接对话框"""
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("连接到远程服务器")
        self.setModal(True)
        self.setFixedSize(400, 200)
        
        layout = QVBoxLayout()
        
        # 服务器地址
        host_layout = QHBoxLayout()
        host_layout.addWidget(QLabel("服务器地址:"))
        self.host_input = QLineEdit("localhost")
        host_layout.addWidget(self.host_input)
        layout.addLayout(host_layout)
        
        # 端口
        port_layout = QHBoxLayout()
        port_layout.addWidget(QLabel("端口:"))
        self.port_input = QLineEdit("8888")
        port_layout.addWidget(self.port_input)
        layout.addLayout(port_layout)
        
        # 密钥
        key_layout = QHBoxLayout()
        key_layout.addWidget(QLabel("连接密钥:"))
        self.key_input = QLineEdit()
        self.key_input.setEchoMode(QLineEdit.Password)
        key_layout.addWidget(self.key_input)
        layout.addLayout(key_layout)
        
        # 按钮
        button_layout = QHBoxLayout()
        self.connect_btn = QPushButton("连接")
        self.connect_btn.clicked.connect(self.accept)
        self.cancel_btn = QPushButton("取消")
        self.cancel_btn.clicked.connect(self.reject)
        button_layout.addWidget(self.connect_btn)
        button_layout.addWidget(self.cancel_btn)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def get_connection_info(self):
        """获取连接信息"""
        return {
            'host': self.host_input.text().strip(),
            'port': int(self.port_input.text().strip()) if self.port_input.text().strip() else 8888,
            'key': self.key_input.text().strip()
        }


class RemoteControlClient:
    """远程控制客户端（核心功能）"""
    def __init__(self, host='localhost', port=8888, secret_key=None):
        self.host = host
        self.port = port
        self.socket = None
        self.connected = False
        self.secret_key = secret_key
        self.fernet = None
        self.authenticated = False
        self.output_callback = None  # 用于接收流式输出的回调函数
        self.recv_thread = None  # 接收线程
        self.recv_running = False  # 接收线程运行标志
    
    def _setup_encryption(self, secret_key):
        """设置加密"""
        if not ENCRYPTION_AVAILABLE:
            return False
        
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'remote_control_salt',
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(secret_key.encode('utf-8')))
            self.fernet = Fernet(key)
            return True
        except Exception as e:
            print(f"[-] 加密设置失败: {e}")
            return False
    
    def _encrypt_data(self, data):
        """加密数据"""
        if not self.fernet:
            return data
        try:
            if isinstance(data, str):
                data = data.encode('utf-8')
            return self.fernet.encrypt(data)
        except Exception as e:
            print(f"[-] 加密失败: {e}")
            return data
    
    def _decrypt_data(self, data):
        """解密数据"""
        if not self.fernet:
            return data
        try:
            return self.fernet.decrypt(data)
        except Exception as e:
            print(f"[-] 解密失败: {e}")
            return data
    
    def _send_encrypted(self, data):
        """发送加密数据"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        if self.fernet:
            encrypted_data = self._encrypt_data(data)
        else:
            encrypted_data = data
        
        size = len(encrypted_data)
        self.socket.sendall(struct.pack('!I', size))
        self.socket.sendall(encrypted_data)
    
    def _recv_encrypted(self):
        """接收并解密数据"""
        size_data = b""
        while len(size_data) < 4:
            chunk = self.socket.recv(4 - len(size_data))
            if not chunk:
                return None
            size_data += chunk
        
        size = struct.unpack('!I', size_data)[0]
        data = b""
        while len(data) < size:
            chunk = self.socket.recv(min(4096, size - len(data)))
            if not chunk:
                return None
            data += chunk
        
        # 如果启用了加密，尝试解密
        if self.fernet:
            try:
                decrypted = self._decrypt_data(data)
                return decrypted
            except Exception as e:
                # 解密失败，可能是未加密的数据（例如认证阶段）
                # 或者数据损坏，返回原始数据
                print(f"[-] 解密失败（可能是未加密数据）: {e}")
                return data
        return data
    
    def _authenticate(self):
        """身份验证"""
        try:
            # 接收认证消息（未加密）
            size_data = b""
            while len(size_data) < 4:
                chunk = self.socket.recv(4 - len(size_data))
                if not chunk:
                    return False, "连接已断开"
                size_data += chunk
            
            size = struct.unpack('!I', size_data)[0]
            auth_data = b""
            while len(auth_data) < size:
                chunk = self.socket.recv(min(4096, size - len(auth_data)))
                if not chunk:
                    return False, "连接已断开"
                auth_data += chunk
            
            auth_msg = auth_data.decode('utf-8', errors='ignore')
            
            if auth_msg == "OK":
                self.authenticated = True
                return True, None
            
            if auth_msg != "AUTH_REQUIRED":
                return False, f"未知的认证消息: {auth_msg}"
            
            if not self.secret_key:
                return False, "需要密钥但未提供"
            
            if not self._setup_encryption(self.secret_key):
                return False, "加密设置失败"
            
            # 发送密钥（加密）
            self._send_encrypted(self.secret_key)
            
            # 接收认证结果（加密）
            result_data = self._recv_encrypted()
            if not result_data:
                return False, "未收到认证结果"
            
            result_msg = result_data.decode('utf-8', errors='ignore')
            
            if result_msg == "AUTH_SUCCESS":
                self.authenticated = True
                return True, None
            else:
                return False, "认证失败: 密钥错误"
                
        except Exception as e:
            return False, f"认证过程出错: {str(e)}"
    
    def connect(self):
        """连接到服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            self.socket.settimeout(60)
            
            # 身份验证
            success, error = self._authenticate()
            if not success:
                self.socket.close()
                self.socket = None
                return False, error
            
            self.connected = True
            
            # 注意：接收线程应该在设置回调函数后启动
            # 这里不启动，由调用者设置回调后手动启动
            # self._start_recv_thread()
            
            return True, None
        except socket.timeout:
            return False, "连接超时"
        except ConnectionRefusedError:
            return False, "连接被拒绝: 请确保被控端正在运行"
        except Exception as e:
            return False, f"连接失败: {str(e)}"
    
    def _start_recv_thread(self):
        """启动接收线程，持续接收服务器发送的流式输出"""
        if self.recv_thread and self.recv_thread.is_alive():
            return
        
        self.recv_running = True
        
        def recv_loop():
            """接收循环"""
            print("[DEBUG] 接收线程已启动")
            while self.recv_running and self.connected and self.socket:
                try:
                    # 设置较短的超时，以便能够及时响应停止信号
                    self.socket.settimeout(1.0)
                    
                    # 接收数据（保留原始控制字节，使用 latin-1 解码以不丢失字节）
                    response_data = self._recv_encrypted()
                    if not response_data:
                        if not self._check_connection():
                            self.connected = False
                        break

                    # 使用 latin-1 解码以直接映射字节到Unicode码位，保留控制字符（例如 ANSI 转义序列）
                    try:
                        text = response_data.decode('latin-1')
                        print(f"[DEBUG] 接收到数据 (latin-1): {repr(text[:100])}")
                        
                        # 直接以字节处理，保留原始字节以便在 GUI 端按不同编码解码
                        raw = response_data
                        if raw.startswith(b"STDOUT:"):
                            payload = raw[7:]
                            print(f"[DEBUG] STDOUT bytes len: {len(payload)}")
                            if self.output_callback:
                                self.output_callback(payload, "stdout")
                            else:
                                print("[DEBUG] 警告: output_callback 未设置")
                        elif raw.startswith(b"STDERR:"):
                            payload = raw[7:]
                            print(f"[DEBUG] STDERR bytes len: {len(payload)}")
                            if self.output_callback:
                                self.output_callback(payload, "stderr")
                            else:
                                print("[DEBUG] 警告: output_callback 未设置")
                        else:
                            # 普通响应（用于兼容旧代码），直接传递字节
                            print(f"[DEBUG] 普通响应 bytes len: {len(raw)}")
                            if self.output_callback:
                                self.output_callback(raw, "response")
                            else:
                                print("[DEBUG] 警告: output_callback 未设置")
                    except Exception as e:
                        print(f"[-] 处理接收数据时出错: {e}")
                        import traceback
                        traceback.print_exc()
                        
                except socket.timeout:
                    # 超时是正常的，继续循环
                    continue
                except Exception as e:
                    if self.recv_running:
                        print(f"[-] 接收线程出错: {e}")
                        import traceback
                        traceback.print_exc()
                    break
            print("[DEBUG] 接收线程已退出")
        
        self.recv_thread = threading.Thread(target=recv_loop, daemon=True)
        self.recv_thread.start()
    
    def _check_connection(self):
        """检查连接是否有效"""
        if not self.socket:
            return False
        try:
            # 使用非阻塞方式检查socket状态
            self.socket.settimeout(0.0)
            try:
                # 尝试接收0字节，检查连接状态
                data = self.socket.recv(1, socket.MSG_PEEK)
                if data == b'':
                    # 连接已关闭
                    return False
            except socket.error:
                # 没有数据可读，但连接可能仍然有效
                pass
            finally:
                # 恢复超时设置
                self.socket.settimeout(60)
            return True
        except:
            return False
    
    def set_output_callback(self, callback):
        """设置输出回调函数，用于接收流式输出
        callback(output, type): type 可以是 'stdout', 'stderr', 'response'
        """
        self.output_callback = callback
    
    def send_command(self, command):
        """发送命令（交互式模式：不等待响应，响应通过回调函数接收）
        返回: (response, error) - response 对于普通命令为 None，响应通过回调函数接收
        """
        if not self.connected or not self.socket:
            return None, "未连接到服务器"
        
        try:
            # 发送命令（加密）
            self._send_encrypted(command)
            
            # 普通命令：只发送，不等待响应（响应通过回调函数接收）
            return None, None
            
        except socket.timeout:
            return None, "发送命令超时"
        except socket.error as e:
            if not self._check_connection():
                self.connected = False
            return None, f"Socket错误: {e}"
        except BrokenPipeError:
            self.connected = False
            return None, "连接已断开"
        except ConnectionResetError:
            self.connected = False
            return None, "连接被重置"
        except Exception as e:
            if not self._check_connection():
                self.connected = False
            return None, f"发送数据时出错: {e}"
    
    def get_screenshot(self):
        """获取截图"""
        if not self.connected:
            return None, "未连接到服务器"

        try:
            # 使用独立短连接请求截图，避免主连接的接收线程竞争数据
            stream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            stream_socket.settimeout(10)
            stream_socket.connect((self.host, self.port))
            stream_socket.settimeout(60)

            # 握手：接收认证消息（未加密）
            size_data = b""
            while len(size_data) < 4:
                chunk = stream_socket.recv(4 - len(size_data))
                if not chunk:
                    stream_socket.close()
                    return None, "连接已断开"
                size_data += chunk

            size = struct.unpack('!I', size_data)[0]
            auth_data = b""
            while len(auth_data) < size:
                chunk = stream_socket.recv(min(4096, size - len(auth_data)))
                if not chunk:
                    stream_socket.close()
                    return None, "连接已断开"
                auth_data += chunk

            auth_msg = auth_data.decode('utf-8', errors='ignore')

            stream_fernet = None
            if auth_msg == 'OK':
                stream_fernet = None
            elif auth_msg == 'AUTH_REQUIRED':
                if not self.fernet:
                    stream_socket.close()
                    return None, '主连接未认证'
                # 发送已认证标记（使用主连接的密钥加密）
                auth_token = 'AUTH_ALREADY_AUTHENTICATED'.encode('utf-8')
                encrypted_token = self.fernet.encrypt(auth_token)
                stream_socket.sendall(struct.pack('!I', len(encrypted_token)))
                stream_socket.sendall(encrypted_token)

                # 接收认证结果
                result_size_data = b""
                while len(result_size_data) < 4:
                    chunk = stream_socket.recv(4 - len(result_size_data))
                    if not chunk:
                        stream_socket.close()
                        return None, '连接已断开'
                    result_size_data += chunk

                result_size = struct.unpack('!I', result_size_data)[0]
                result_data = b""
                while len(result_data) < result_size:
                    chunk = stream_socket.recv(min(4096, result_size - len(result_data)))
                    if not chunk:
                        stream_socket.close()
                        return None, '连接已断开'
                    result_data += chunk

                # 使用主连接的 fernet 解密结果
                try:
                    result_msg = self.fernet.decrypt(result_data).decode('utf-8', errors='ignore')
                except Exception:
                    stream_socket.close()
                    return None, '认证失败'

                if result_msg != 'AUTH_SUCCESS':
                    stream_socket.close()
                    return None, '认证失败'
                stream_fernet = self.fernet
            else:
                stream_socket.close()
                return None, f'未知的认证消息: {auth_msg}'

            # 发送截图命令
            cmd = 'screenshot -q 70 -s 0.5'
            if stream_fernet:
                payload = stream_fernet.encrypt(cmd.encode('utf-8'))
            else:
                payload = cmd.encode('utf-8')
            stream_socket.sendall(struct.pack('!I', len(payload)))
            stream_socket.sendall(payload)

            # 接收返回的数据
            size_data = b""
            while len(size_data) < 4:
                chunk = stream_socket.recv(4 - len(size_data))
                if not chunk:
                    stream_socket.close()
                    return None, '未收到截图数据'
                size_data += chunk

            size = struct.unpack('!I', size_data)[0]
            data = b""
            while len(data) < size:
                chunk = stream_socket.recv(min(4096, size - len(data)))
                if not chunk:
                    stream_socket.close()
                    return None, '未收到完整截图数据'
                data += chunk

            if stream_fernet:
                try:
                    image_data = stream_fernet.decrypt(data)
                except Exception:
                    stream_socket.close()
                    return None, '解密截图数据失败'
            else:
                image_data = data

            # 检查是否为错误消息
            try:
                text = image_data.decode('utf-8', errors='ignore')
                if text.startswith('截图失败') or text.startswith('截图功能不可用') or text.startswith('ERROR'):
                    stream_socket.close()
                    return None, text
            except Exception:
                pass

            stream_socket.close()
            return image_data, None

        except Exception as e:
            return None, f"获取截图失败: {str(e)}"
    
    def start_stream(self, fps=5, quality=50, scale=0.5):
        """启动画面流（返回socket和fernet对象）
        注意：复用主连接的认证信息，不再进行额外认证
        """
        try:
            stream_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            stream_socket.settimeout(10)
            stream_socket.connect((self.host, self.port))
            stream_socket.settimeout(60)
            
            # 接收认证消息（与服务端握手，但使用已认证的密钥）
            size_data = b""
            while len(size_data) < 4:
                chunk = stream_socket.recv(4 - len(size_data))
                if not chunk:
                    stream_socket.close()
                    return None, None, "连接已断开"
                size_data += chunk
            
            size = struct.unpack('!I', size_data)[0]
            auth_data = b""
            while len(auth_data) < size:
                chunk = stream_socket.recv(min(4096, size - len(auth_data)))
                if not chunk:
                    stream_socket.close()
                    return None, None, "连接已断开"
                auth_data += chunk
            
            auth_msg = auth_data.decode('utf-8')
            
            if auth_msg == "OK":
                # 服务器未设置密钥，直接使用
                return stream_socket, None, None
            
            if auth_msg == "AUTH_REQUIRED":
                # 服务器需要认证，但我们已经认证过了，直接发送已认证标记
                # 复用主连接的fernet对象
                if self.fernet:
                    # 发送一个已认证标记（使用主连接的密钥加密）
                    auth_token = "AUTH_ALREADY_AUTHENTICATED"
                    encrypted_token = self.fernet.encrypt(auth_token.encode('utf-8'))
                    stream_socket.sendall(struct.pack('!I', len(encrypted_token)))
                    stream_socket.sendall(encrypted_token)
                    
                    # 接收确认（应该返回AUTH_SUCCESS）
                    result_size_data = b""
                    while len(result_size_data) < 4:
                        chunk = stream_socket.recv(4 - len(result_size_data))
                        if not chunk:
                            stream_socket.close()
                            return None, None, "连接已断开"
                        result_size_data += chunk
                    
                    result_size = struct.unpack('!I', result_size_data)[0]
                    result_data = b""
                    while len(result_data) < result_size:
                        chunk = stream_socket.recv(min(4096, result_size - len(result_data)))
                        if not chunk:
                            stream_socket.close()
                            return None, None, "连接已断开"
                        result_data += chunk
                    
                    result_msg = self.fernet.decrypt(result_data).decode('utf-8')
                    
                    if result_msg == "AUTH_SUCCESS":
                        return stream_socket, self.fernet, None
                    else:
                        stream_socket.close()
                        return None, None, "认证失败"
                else:
                    # 没有加密对象，说明主连接也未认证，不应该到这里
                    stream_socket.close()
                    return None, None, "主连接未认证"
            else:
                stream_socket.close()
                return None, None, f"未知的认证消息: {auth_msg}"
        except Exception as e:
            return None, None, f"连接失败: {str(e)}"
    
    def disconnect(self):
        """断开连接"""
        # 停止接收线程
        self.recv_running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
        self.connected = False


class StreamThread(QThread):
    """画面流接收线程"""
    frame_received = pyqtSignal(bytes)
    error_occurred = pyqtSignal(str)
    finished_signal = pyqtSignal()
    
    def __init__(self, stream_socket, stream_fernet, fps=5, quality=50, scale=0.5):
        super().__init__()
        self.stream_socket = stream_socket
        self.stream_fernet = stream_fernet
        self.fps = fps
        self.quality = quality
        self.scale = scale
        self.running = True
    
    def stop(self):
        """停止流传输"""
        self.running = False
    
    def run(self):
        """运行线程"""
        try:
            # 发送流命令（加密）
            cmd = f"stream -fps {self.fps} -q {self.quality} -s {self.scale}"
            if self.stream_fernet:
                encrypted_cmd = self.stream_fernet.encrypt(cmd.encode('utf-8'))
            else:
                encrypted_cmd = cmd.encode('utf-8')
            
            self.stream_socket.sendall(struct.pack('!I', len(encrypted_cmd)))
            self.stream_socket.sendall(encrypted_cmd)
            
            # 发送停止流命令的函数
            def send_stop():
                stop_cmd = "stop_stream"
                if self.stream_fernet:
                    encrypted_stop = self.stream_fernet.encrypt(stop_cmd.encode('utf-8'))
                else:
                    encrypted_stop = stop_cmd.encode('utf-8')
                try:
                    self.stream_socket.sendall(struct.pack('!I', len(encrypted_stop)))
                    self.stream_socket.sendall(encrypted_stop)
                except:
                    pass
            
            self.send_stop = send_stop
            
            while self.running:
                try:
                    # 接收加密的图片数据
                    size_data = b""
                    while len(size_data) < 4:
                        chunk = self.stream_socket.recv(4 - len(size_data))
                        if not chunk:
                            self.running = False
                            break
                        size_data += chunk
                    
                    if not self.running:
                        break
                    
                    size = struct.unpack('!I', size_data)[0]
                    
                    # 接收加密数据
                    encrypted_data = b""
                    while len(encrypted_data) < size:
                        chunk = self.stream_socket.recv(min(4096, size - len(encrypted_data)))
                        if not chunk:
                            self.running = False
                            break
                        encrypted_data += chunk
                    
                    if not self.running:
                        break
                    
                    # 解密图片数据
                    if self.stream_fernet:
                        image_data = self.stream_fernet.decrypt(encrypted_data)
                    else:
                        image_data = encrypted_data
                    
                    # 检查是否是错误消息或文本数据（命令输出）
                    if len(image_data) < 100:
                        try:
                            error_msg = image_data.decode('utf-8')
                            if error_msg.startswith("ERROR") or error_msg.startswith("错误"):
                                self.error_occurred.emit(error_msg)
                                break
                            # 如果是命令输出（STDOUT/STDERR），跳过
                            if error_msg.startswith("STDOUT:") or error_msg.startswith("STDERR:"):
                                continue
                        except:
                            pass
                    
                    # 验证是否是有效的图片数据（检查图片魔数）
                    if not (image_data.startswith(b'\xff\xd8\xff') or  # JPEG
                            image_data.startswith(b'\x89PNG') or      # PNG
                            image_data.startswith(b'GIF87a') or       # GIF87a
                            image_data.startswith(b'GIF89a')):        # GIF89a
                        # 不是图片数据，可能是文本数据，跳过
                        continue
                    
                    # 发送图片数据信号
                    self.frame_received.emit(image_data)
                    
                    # 控制帧率
                    time.sleep(1.0 / self.fps)
                    
                except Exception as e:
                    self.error_occurred.emit(f"接收画面数据失败: {str(e)}")
                    break
                    
        except Exception as e:
            self.error_occurred.emit(f"画面流线程出错: {str(e)}")
        finally:
            self.finished_signal.emit()


class CommandThread(QThread):
    """命令执行线程（已废弃，现在使用回调函数）"""
    command_result = pyqtSignal(str, str)  # response, error
    
    def __init__(self, client, command):
        super().__init__()
        self.client = client
        self.command = command
    
    def run(self):
        """执行命令"""
        try:
            response, error = self.client.send_command(self.command)
            # 发送结果信号（确保response和error都是字符串）
            response_str = response if response else ""
            error_str = error if error else ""
            self.command_result.emit(response_str, error_str)
        except Exception as e:
            self.command_result.emit("", str(e))


class RemoteControlGUI(QMainWindow):
    """远程控制GUI主窗口"""
    def __init__(self):
        super().__init__()
        self.client = None
        # 线程安全的信号对象，用于跨线程请求主线程恢复按钮状态
        class _SignalObject(QObject):
            restore_screenshot = pyqtSignal()

        self._sigobj = _SignalObject()
        self._sigobj.restore_screenshot.connect(self._on_restore_screenshot)

        self.stream_thread = None
        self.stream_socket = None
        self.command_thread = None
        self._pending_output = ""
        self._pending_output_type = ""
        # 帧计数与 FPS 定时更新
        self._frames_received_count = 0
        self._last_fps = 0
        self._fps_timer = QTimer()
        self._fps_timer.timeout.connect(self._refresh_fps_display)
        self._fps_timer.start(1000)
        self.init_ui()

    def _on_restore_screenshot(self):
        try:
            self.screenshot_btn.setEnabled(True)
            self.screenshot_btn.setText("📷 截图")
        except Exception:
            pass
    
    def init_ui(self):
        """初始化UI"""
        self.setWindowTitle("远程控制客户端")
        # 增大窗口尺寸以适配标准分辨率（1920x1080的缩放显示）
        self.setGeometry(100, 100, 1600, 1000)
        
        # 中央部件
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # 主布局
        main_layout = QVBoxLayout()
        main_layout.setSpacing(5)
        main_layout.setContentsMargins(5, 5, 5, 5)
        central_widget.setLayout(main_layout)
        
        # 创建标签页
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # Tab 1: 画面监控
        screen_tab = QWidget()
        screen_layout = QVBoxLayout()
        screen_layout.setSpacing(5)
        screen_layout.setContentsMargins(5, 5, 5, 5)
        screen_tab.setLayout(screen_layout)
        
        # 画面显示区域
        self.screen_label = QLabel("等待连接...")
        self.screen_label.setMinimumSize(1280, 720)
        self.screen_label.setAlignment(Qt.AlignCenter)
        self.screen_label.setStyleSheet("background-color: black; color: white; border: 2px solid #555;")
        self.screen_label.setScaledContents(False)
        screen_layout.addWidget(self.screen_label)
        
        # 状态栏
        self.status_label = QLabel("未连接")
        self.status_label.setStyleSheet("background-color: #333; color: white; padding: 8px; font-size: 12px;")
        self.status_label.setMaximumHeight(30)
        screen_layout.addWidget(self.status_label)
        # 初始化手动 FPS 控件（放在按钮区以避免新增区域）
        from PyQt5.QtWidgets import QSpinBox
        self.fps_input = QSpinBox()
        self.fps_input.setRange(1, 120)
        self.fps_input.setValue(5)
        self.fps_input.setMaximumWidth(80)

        self.apply_fps_btn = QPushButton("设置FPS并重启流")
        self.apply_fps_btn.setMinimumHeight(28)
        self.apply_fps_btn.clicked.connect(lambda: self._apply_manual_fps())

        # 当前流参数（用于手动调整时保持其他参数）
        self._current_stream_params = {'fps': 5, 'quality': 50, 'scale': 0.75}

        
        # 功能按钮区域
        screen_btn_layout = QHBoxLayout()
        screen_btn_layout.setSpacing(10)
        
        self.screenshot_btn = QPushButton("📷 截图")
        self.screenshot_btn.setMinimumHeight(35)
        self.screenshot_btn.clicked.connect(self.take_screenshot)
        self.screenshot_btn.setStyleSheet("font-size: 12px;")
        screen_btn_layout.addWidget(self.screenshot_btn)
        
        self.disconnect_btn = QPushButton("🔌 断开连接")
        self.disconnect_btn.setMinimumHeight(35)
        self.disconnect_btn.clicked.connect(self.disconnect)
        self.disconnect_btn.setStyleSheet("font-size: 12px; background-color: #dc3545; color: white;")
        screen_btn_layout.addWidget(self.disconnect_btn)
        # 预设流设置按钮
        self.preset_lowlat_btn = QPushButton("低延迟: 15fps")
        self.preset_lowlat_btn.setMinimumHeight(35)
        self.preset_lowlat_btn.clicked.connect(lambda: self.start_stream(fps=15, quality=60, scale=1.0))
        screen_btn_layout.addWidget(self.preset_lowlat_btn)

        self.preset_balanced_btn = QPushButton("平衡: 5fps")
        self.preset_balanced_btn.setMinimumHeight(35)
        self.preset_balanced_btn.clicked.connect(lambda: self.start_stream(fps=5, quality=50, scale=0.75))
        screen_btn_layout.addWidget(self.preset_balanced_btn)

        self.preset_lowbw_btn = QPushButton("省带宽: 1fps")
        self.preset_lowbw_btn.setMinimumHeight(35)
        self.preset_lowbw_btn.clicked.connect(lambda: self.start_stream(fps=1, quality=30, scale=0.5))
        screen_btn_layout.addWidget(self.preset_lowbw_btn)

        # 手动 FPS 控件（集成在按钮区域）
        fps_label = QLabel("FPS:")
        fps_label.setStyleSheet("color: #8b949e;")
        screen_btn_layout.addWidget(fps_label)
        screen_btn_layout.addWidget(self.fps_input)
        screen_btn_layout.addWidget(self.apply_fps_btn)

        screen_btn_layout.addStretch()
        screen_layout.addLayout(screen_btn_layout)
        
        self.tabs.addTab(screen_tab, "📺 画面监控")
        
        # Tab 2: 终端（命令执行）- 优化布局
        terminal_tab = QWidget()
        terminal_layout = QVBoxLayout()
        terminal_layout.setSpacing(0)
        terminal_layout.setContentsMargins(0, 0, 0, 0)
        terminal_tab.setLayout(terminal_layout)
        
        # 顶部状态栏（更简洁）
        status_bar = QWidget()
        status_bar.setMaximumHeight(35)
        status_bar.setStyleSheet("background-color: #1a1a1a; border-bottom: 1px solid #333;")
        status_layout = QHBoxLayout()
        status_layout.setContentsMargins(10, 5, 10, 5)
        status_layout.setSpacing(15)
        status_bar.setLayout(status_layout)
        
        info_label = QLabel("连接:")
        info_label.setStyleSheet("color: #888; font-family: 'Consolas', monospace; font-size: 11px;")
        status_layout.addWidget(info_label)
        
        self.connection_info = QLabel("未连接")
        self.connection_info.setStyleSheet("color: #00ff00; font-family: 'Consolas', monospace; font-size: 11px;")
        status_layout.addWidget(self.connection_info)
        status_layout.addStretch()
        terminal_layout.addWidget(status_bar)
        
        # 终端输出区域（全屏，更美观）
        self.cmd_output = QTextEdit()
        self.cmd_output.setReadOnly(True)
        self.cmd_output.setAcceptRichText(True)
        # 优化的终端风格样式
        self.cmd_output.setStyleSheet("""
            QTextEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                font-family: 'Consolas', 'Courier New', 'Monaco', monospace;
                font-size: 14px;
                padding: 15px;
                border: none;
                selection-background-color: #264f78;
                line-height: 1.5;
            }
        """)
        terminal_layout.addWidget(self.cmd_output)
        
        # 底部命令输入栏（固定在底部）
        input_bar = QWidget()
        input_bar.setMaximumHeight(50)
        input_bar.setStyleSheet("background-color: #161b22; border-top: 2px solid #30363d;")
        cmd_input_layout = QHBoxLayout()
        cmd_input_layout.setContentsMargins(10, 8, 10, 8)
        cmd_input_layout.setSpacing(10)
        input_bar.setLayout(cmd_input_layout)
        
        # 提示符（更明显）
        prompt_label = QLabel("$")
        prompt_label.setStyleSheet("color: #58a6ff; font-family: 'Consolas', monospace; font-size: 16px; font-weight: bold; min-width: 20px;")
        cmd_input_layout.addWidget(prompt_label)
        
        self.cmd_input = QLineEdit()
        self.cmd_input.setPlaceholderText("输入命令并按回车执行...")
        self.cmd_input.returnPressed.connect(self.execute_command)
        self.cmd_input.setStyleSheet("""
            QLineEdit {
                background-color: #0d1117;
                color: #c9d1d9;
                font-family: 'Consolas', 'Courier New', monospace;
                font-size: 14px;
                padding: 8px 12px;
                border: 1px solid #30363d;
                border-radius: 4px;
            }
            QLineEdit:focus {
                border: 1px solid #58a6ff;
                background-color: #161b22;
            }
        """)
        cmd_input_layout.addWidget(self.cmd_input)
        
        self.cmd_btn = QPushButton("执行")
        self.cmd_btn.setMinimumWidth(90)
        self.cmd_btn.setMaximumWidth(90)
        self.cmd_btn.clicked.connect(self.execute_command)
        self.cmd_btn.setStyleSheet("""
            QPushButton {
                background-color: #238636;
                color: #ffffff;
                font-family: 'Consolas', monospace;
                font-size: 13px;
                font-weight: bold;
                padding: 8px 16px;
                border: none;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2ea043;
            }
            QPushButton:pressed {
                background-color: #1e6e2e;
            }
            QPushButton:disabled {
                background-color: #1a4726;
                color: #6e7681;
            }
        """)
        cmd_input_layout.addWidget(self.cmd_btn)
        terminal_layout.addWidget(input_bar)
        
        # 初始化终端欢迎信息（使用HTML格式，更美观）
        welcome_text = """
        <div style="color: #58a6ff; font-weight: bold; margin-bottom: 10px;">
        ╔═══════════════════════════════════════════════════════════════╗
        ║                   远程控制终端 v1.0                           ║
        ╚═══════════════════════════════════════════════════════════════╝
        </div>
        <div style="color: #8b949e; margin-top: 10px;">
        等待连接服务器...
        </div>
        """
        self.cmd_output.append(welcome_text)
        self.cmd_output.append("")
        
        self.tabs.addTab(terminal_tab, "💻 终端")
        
        # 显示连接对话框
        self.show_connection_dialog()
    
    def show_connection_dialog(self):
        """显示连接对话框"""
        dialog = ConnectionDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            info = dialog.get_connection_info()
            self.connect_to_server(info['host'], info['port'], info['key'])
        else:
            sys.exit(0)
    
    def connect_to_server(self, host, port, key):
        """连接到服务器"""
        self.status_label.setText("正在连接...")
        self.connection_info.setText(f"服务器: {host}:{port} | 密钥: {'已设置' if key else '未设置'}")
        
        # 在终端显示连接信息
        import html
        escaped_host = html.escape(f'{host}:{port}')
        self.cmd_output.insertHtml(f'<span style="color: #f85149;">[*] 正在连接到 {escaped_host}...</span><br>')
        
        # 创建客户端
        self.client = RemoteControlClient(host=host, port=port, secret_key=key)
        
        # 连接
        success, error = self.client.connect()
        if not success:
            QMessageBox.critical(self, "连接失败", f"无法连接到服务器:\n{error}")
            self.show_connection_dialog()
            return
        
        self.status_label.setText("已连接")
        self.connection_info.setText(f"服务器: {host}:{port} | 状态: 已连接 | 加密: {'已启用' if key else '未启用'}")
        
        # 在终端显示连接成功信息（更美观）
        import html
        escaped_host = html.escape(f'{host}:{port}')
        self.cmd_output.insertHtml(f'<span style="color: #3fb950;">[+] 成功连接到服务器 <span style="color: #58a6ff;">{escaped_host}</span></span><br>')
        encryption_status = '已启用' if key else '未启用'
        encryption_color = '#3fb950' if key else '#8b949e'
        self.cmd_output.insertHtml(f'<span style="color: {encryption_color};">[+] 加密传输: {encryption_status}</span><br>')
        self.cmd_output.insertHtml('<br>')
        self.cmd_output.insertHtml('<span style="color: #58a6ff;">✓ 终端已就绪，可以输入命令...</span><br>')
        self.cmd_output.insertHtml('<span style="color: #6e7681;">─────────────────────────────────────────────────────────────</span><br>')
        self.cmd_output.insertHtml('<br>')
        # 滚动到底部
        from PyQt5.QtGui import QTextCursor
        cursor = self.cmd_output.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.cmd_output.setTextCursor(cursor)
        
        # 设置输出回调函数，用于接收流式输出
        print("[DEBUG] 设置输出回调函数")
        self.client.set_output_callback(self.on_output_received)
        print(f"[DEBUG] 回调函数已设置: {self.client.output_callback is not None}")
        
        # 设置回调后，启动接收线程
        if not self.client.recv_thread or not self.client.recv_thread.is_alive():
            print("[DEBUG] 启动接收线程")
            self.client._start_recv_thread()
        
        # 启动画面流
        self.start_stream()
    
    def on_output_received(self, output, output_type):
        """处理接收到的流式输出（可能在工作线程中调用，需要使用QTimer调度到主线程）"""
        print(f"[DEBUG] on_output_received 被调用: type={output_type}, output={(output[:50] if isinstance(output, (bytes, bytearray)) else repr(output[:50]))}")
        # 保存参数到实例变量，避免闭包问题（output 现在是 bytes）
        self._pending_output = output
        self._pending_output_type = output_type
        
        # 使用 QTimer.singleShot 确保在主线程中执行 UI 更新
        QTimer.singleShot(0, self._update_output_ui)
    
    def _update_output_ui(self):
        """更新输出UI（在主线程中调用）"""
        import html
        
        def ansi_to_html(text: str) -> str:
            """将 ANSI 控制序列转换为简单的 HTML span 样式。
            只实现常见 SGR 颜色和样式（reset, bold, underline, fg/bg 颜色）。
            输入应为 latin-1 解码得到的字符串，函数会做 HTML 转义并返回安全的 HTML。"""
            # 基本颜色映射（30-37 / 90-97）
            fg_colors = {
                30: '#000000', 31: '#aa0000', 32: '#00aa00', 33: '#aa5500',
                34: '#0000aa', 35: '#aa00aa', 36: '#00aaaa', 37: '#aaaaaa',
                90: '#555555', 91: '#ff5555', 92: '#55ff55', 93: '#ffff55',
                94: '#5555ff', 95: '#ff55ff', 96: '#55ffff', 97: '#ffffff'
            }
            bg_colors = {
                40: '#000000', 41: '#aa0000', 42: '#00aa00', 43: '#aa5500',
                44: '#0000aa', 45: '#aa00aa', 46: '#00aaaa', 47: '#aaaaaa',
                100: '#555555', 101: '#ff5555', 102: '#55ff55', 103: '#ffff55',
                104: '#5555ff', 105: '#ff55ff', 106: '#55ffff', 107: '#ffffff'
            }

            esc_re = re.compile(r'\x1b\[([0-9;]*)m')

            parts = esc_re.split(text)
            # parts alternates: [text, params, text, params, ...]
            html_parts = []
            open_styles = []  # stack of open span styles

            def close_all():
                s = ''.join('</span>' for _ in open_styles)
                open_styles.clear()
                return s

            i = 0
            while i < len(parts):
                chunk = parts[i]
                # plain text chunk - escape and append
                if chunk:
                    html_parts.append(html.escape(chunk).replace('\n', '<br>'))

                if i + 1 < len(parts):
                    params = parts[i + 1]
                    if params == '':
                        params_list = [0]
                    else:
                        try:
                            params_list = [int(p) if p else 0 for p in params.split(';')]
                        except:
                            params_list = [0]

                    # process params
                    style = {}
                    close_on_reset = False
                    for p in params_list:
                        if p == 0:
                            # reset
                            html_parts.append(close_all())
                        elif p == 1:
                            style['font-weight'] = 'bold'
                        elif p == 4:
                            style['text-decoration'] = 'underline'
                        elif 30 <= p <= 37 or 90 <= p <= 97:
                            if p in fg_colors:
                                style['color'] = fg_colors[p]
                        elif 40 <= p <= 47 or 100 <= p <= 107:
                            if p in bg_colors:
                                style['background-color'] = bg_colors[p]
                        elif p == 39:
                            # reset fg
                            if 'color' in style:
                                del style['color']
                        elif p == 49:
                            if 'background-color' in style:
                                del style['background-color']
                        # 其他代码暂不处理

                    if style:
                        # open a new span with the accumulated style
                        css = ';'.join(f'{k}:{v}' for k, v in style.items())
                        html_parts.append(f'<span style="{css}">')
                        open_styles.append(True)

                i += 2

            # close remaining
            if open_styles:
                html_parts.append(close_all())

            return ''.join(html_parts)

        
        try:
            output_bytes = self._pending_output
            output_type = self._pending_output_type
            # 输出现在是 bytes：优先检测 UTF-8（通常现代程序），失败后尝试 cp936（Windows），最后 latin-1
            def detect_decode(b: bytes) -> str:
                try:
                    return b.decode('utf-8')
                except Exception:
                    try:
                        return b.decode('cp936')
                    except Exception:
                        return b.decode('latin-1', errors='ignore')

            decoded = detect_decode(output_bytes)

            # 规范化回车/换行：将 CRLF -> LF，并处理单独的 CR 覆盖行为
            def normalize_cr(text: str) -> str:
                # 将CRLF统一为LF
                text = text.replace('\r\n', '\n')
                # 对于仍包含单独 CR 的片段，取最后一段（CR 覆盖前面的内容）
                parts = text.split('\n')
                out_parts = []
                for seg in parts:
                    if '\r' in seg:
                        seg = seg.split('\r')[-1]
                    out_parts.append(seg)
                # 折叠超过两个连续空行为最多两个空行
                joined = '\n'.join(out_parts)
                joined = re.sub(r'(\n){3,}', '\n\n', joined)
                return joined

            decoded = normalize_cr(decoded)

            print(f"[DEBUG] _update_output_ui 执行中: type={output_type}, decoded sample={repr(decoded[:120])}")

            # 将 ANSI 控制序列转换为 HTML（保留控制字符效果）
            try:
                html_content = ansi_to_html(decoded)
            except Exception:
                # 回退到简单转义
                html_content = html.escape(decoded).replace('\n', '<br>')

            # 插入HTML内容（ansi_to_html 已处理换行）
            self.cmd_output.insertHtml(html_content)
            
            # 自动滚动到底部
            from PyQt5.QtGui import QTextCursor
            cursor = self.cmd_output.textCursor()
            cursor.movePosition(QTextCursor.End)
            self.cmd_output.setTextCursor(cursor)
            
            # 确保滚动到底部
            scrollbar = self.cmd_output.verticalScrollBar()
            if scrollbar:
                scrollbar.setValue(scrollbar.maximum())
            
            print(f"[DEBUG] UI更新完成")
        except Exception as e:
            print(f"[-] 处理输出时出错: {e}")
            import traceback
            traceback.print_exc()
    
    def start_stream(self, fps=5, quality=50, scale=0.5):
        """启动画面流，参数可调：fps, quality, scale
        会在启动前停止任何已有的流。"""
        if not self.client or not self.client.connected:
            return

        # 停止已有流（如果有）
        if self.stream_thread:
            try:
                if hasattr(self.stream_thread, 'send_stop'):
                    try:
                        self.stream_thread.send_stop()
                    except:
                        pass
                self.stream_thread.stop()
                self.stream_thread.wait(1000)
            except Exception:
                pass
        if self.stream_socket:
            try:
                self.stream_socket.close()
            except:
                pass
            self.stream_socket = None

        # 更新当前流参数并刷新说明标签
        self._current_stream_params = {'fps': fps, 'quality': quality, 'scale': scale}
        self._update_stream_info_label()

        # 创建画面流连接
        stream_socket, stream_fernet, error = self.client.start_stream(fps=fps, quality=quality, scale=scale)
        if error:
            QMessageBox.critical(self, "画面流启动失败", error)
            return
        
        self.stream_socket = stream_socket
        # 创建画面流线程
        self.stream_thread = StreamThread(stream_socket, stream_fernet, fps=fps, quality=quality, scale=scale)
        self.stream_thread.frame_received.connect(self.update_frame)
        self.stream_thread.error_occurred.connect(self.handle_stream_error)
        self.stream_thread.finished_signal.connect(self.on_stream_finished)
        self.stream_thread.start()
        
        self.status_label.setText("已连接 - 画面流运行中")
        # 更新说明（保证与实际参数一致）
        self._update_stream_info_label()

    def _update_stream_info_label(self):
        try:
            p = self._current_stream_params
            fps = getattr(self, '_last_fps', p.get('fps', 0))
            # 使用表格布局在左侧显示设置，右侧显示实时FPS
            txt = f"<table width='100%'><tr><td align='left'>当前设置: FPS={p['fps']}, 质量={p['quality']}, 缩放={p['scale']}</td><td align='right'>FPS: {fps}</td></tr></table>"
            self.status_label.setText(txt)
        except Exception:
            pass

    def _refresh_fps_display(self):
        try:
            # 每秒读取计数并重置
            fps = self._frames_received_count
            self._last_fps = fps
            self._frames_received_count = 0
            # 刷新状态栏文本以显示最新FPS
            try:
                self._update_stream_info_label()
            except Exception:
                pass
        except Exception:
            pass

    def _apply_manual_fps(self):
        try:
            fps = int(self.fps_input.value())
            # 使用现有的 quality/scale
            q = self._current_stream_params.get('quality', 50)
            s = self._current_stream_params.get('scale', 0.75)
            self.start_stream(fps=fps, quality=q, scale=s)
        except Exception:
            pass
    
    def update_frame(self, image_data):
        """更新画面帧（在主线程中调用）"""
        try:
            # 统计收到的帧以计算实际FPS
            try:
                self._frames_received_count += 1
            except Exception:
                pass
            # 验证数据是否有效
            if not image_data or len(image_data) < 100:
                # 数据太短，可能是错误消息
                return
            
            # 再次验证是否是有效的图片数据（双重检查）
            if not (image_data.startswith(b'\xff\xd8\xff') or  # JPEG
                    image_data.startswith(b'\x89PNG') or      # PNG
                    image_data.startswith(b'GIF87a') or       # GIF87a
                    image_data.startswith(b'GIF89a')):        # GIF89a
                # 不是有效的图片格式，可能是其他数据，忽略
                return
            
            # 将字节数据转换为QImage
            img = Image.open(io.BytesIO(image_data))
            img_rgb = img.convert('RGB')
            
            # 转换为QImage
            width, height = img_rgb.size
            q_image = QImage(img_rgb.tobytes(), width, height, QImage.Format_RGB888)
            
            # 缩放以适应标签大小
            pixmap = QPixmap.fromImage(q_image)
            # 获取标签的当前大小，如果为0则使用默认大小
            label_size = self.screen_label.size()
            if label_size.width() == 0 or label_size.height() == 0:
                label_size = self.screen_label.minimumSize()
            scaled_pixmap = pixmap.scaled(label_size, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            
            self.screen_label.setPixmap(scaled_pixmap)
            
        except Exception as e:
            print(f"[-] 更新画面失败: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_stream_error(self, error_msg):
        """处理画面流错误"""
        self.status_label.setText(f"画面流错误: {error_msg}")
        QMessageBox.warning(self, "画面流错误", error_msg)
    
    def on_stream_finished(self):
        """画面流结束"""
        self.status_label.setText("画面流已停止")
    
    def execute_command(self):
        """执行命令"""
        if not self.client or not self.client.connected:
            QMessageBox.warning(self, "未连接", "请先连接到服务器")
            return
        
        command = self.cmd_input.text().strip()
        if not command:
            return
        
        # 处理特殊命令
        if command.lower() == 'exit' or command.lower() == 'quit':
            self.disconnect()
            return
        
        # 终端风格显示命令（更美观）
        timestamp = datetime.now().strftime('%H:%M:%S')
        # 转义命令中的HTML特殊字符
        import html
        escaped_command = html.escape(command)
        prompt = f'<span style="color: #6e7681;">[{timestamp}]</span> <span style="color: #58a6ff;">$</span> <span style="color: #c9d1d9;">{escaped_command}</span><br>'
        self.cmd_output.insertHtml(prompt)
        self.cmd_input.clear()
        # 立即滚动到底部
        from PyQt5.QtGui import QTextCursor
        cursor = self.cmd_output.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.cmd_output.setTextCursor(cursor)
        
        # 禁用按钮，防止重复点击
        self.cmd_btn.setEnabled(False)
        
        # 发送命令（交互式模式：不等待响应，响应通过回调函数接收）
        def send_cmd():
            try:
                response, error = self.client.send_command(command)
                if error:
                    # 发送命令时出错
                    def show_error():
                        import html
                        from PyQt5.QtGui import QTextCursor
                        escaped_error = html.escape(error)
                        self.cmd_output.insertHtml(f'<span style="color: #f85149;">[-] 错误: {escaped_error}</span><br><br>')
                        cursor = self.cmd_output.textCursor()
                        cursor.movePosition(QTextCursor.End)
                        self.cmd_output.setTextCursor(cursor)
                        self.cmd_btn.setEnabled(True)
                    QTimer.singleShot(0, show_error)
                else:
                    # 命令已发送，输出会通过回调函数实时显示
                    # 恢复按钮
                    QTimer.singleShot(0, lambda: self.cmd_btn.setEnabled(True))
            except Exception as e:
                def show_exception():
                    import html
                    from PyQt5.QtGui import QTextCursor
                    escaped_error = html.escape(str(e))
                    self.cmd_output.insertHtml(f'<span style="color: #f85149;">[-] 执行命令时出错: {escaped_error}</span><br><br>')
                    cursor = self.cmd_output.textCursor()
                    cursor.movePosition(QTextCursor.End)
                    self.cmd_output.setTextCursor(cursor)
                    self.cmd_btn.setEnabled(True)
                QTimer.singleShot(0, show_exception)
        
        # 在后台线程发送命令
        thread = threading.Thread(target=send_cmd, daemon=True)
        thread.start()

        # 如果是 PTY 模式，打开交互终端并切换回调
        try:
            if command.lower().startswith('pty:'):
                # 发送 PTY 启动命令（立即发送原始命令字符串）
                try:
                    self.client._send_encrypted(command)
                except Exception:
                    pass

                # 创建交互终端窗口
                term = TerminalDialog(self.client, parent=self, title=f"远程终端: {escaped_command}")

                # 切换客户端回调到终端窗口
                self.client.set_output_callback(term.on_output_received)

                # 当终端被关闭时，恢复回调到 GUI 主视图
                def _restore_callback(obj=None):
                    try:
                        self.client.set_output_callback(self.on_output_received)
                    except:
                        pass

                term.destroyed.connect(_restore_callback)

                term.show()
                term.raise_()
                term.activateWindow()
        except Exception:
            pass
    
    def take_screenshot(self):
        """截图"""
        if not self.client or not self.client.connected:
            QMessageBox.warning(self, "未连接", "请先连接到服务器")
            return
        
        # 禁用按钮，防止重复点击
        self.screenshot_btn.setEnabled(False)
        self.screenshot_btn.setText("截图中...")
        
        def do_screenshot():
            try:
                print("[DEBUG] do_screenshot: 开始请求截图")
                image_data, error = self.client.get_screenshot()
                print(f"[DEBUG] do_screenshot: get_screenshot 返回, error={error}, image_len={len(image_data) if image_data else None}")
                if error:
                    # 使用QTimer在主线程中显示消息框和恢复按钮
                    def show_error():
                        QMessageBox.critical(self, "截图失败", error)
                        self.screenshot_btn.setEnabled(True)
                        self.screenshot_btn.setText("📷 截图")
                    QTimer.singleShot(0, show_error)
                else:
                    # 保存截图
                    screenshot_dir = os.path.join(os.getcwd(), "screenshot")
                    if not os.path.exists(screenshot_dir):
                        os.makedirs(screenshot_dir)
                    
                    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                    save_path = os.path.join(screenshot_dir, f"screenshot_{timestamp}.jpg")
                    
                    with open(save_path, 'wb') as f:
                        f.write(image_data)
                    print(f"[DEBUG] do_screenshot: 已写入文件 {save_path}")
                    
                    # 使用QTimer在主线程中显示消息框和恢复按钮
                    def show_success():
                        QMessageBox.information(self, "截图成功", f"截图已保存到:\n{save_path}")
                        self.screenshot_btn.setEnabled(True)
                        self.screenshot_btn.setText("📷 截图")
                    QTimer.singleShot(0, show_success)
            except Exception as e:
                # 使用QTimer在主线程中显示错误和恢复按钮
                def show_exception():
                    QMessageBox.critical(self, "截图失败", f"截图时出错: {str(e)}")
                    self.screenshot_btn.setEnabled(True)
                    self.screenshot_btn.setText("📷 截图")
                QTimer.singleShot(0, show_exception)
            finally:
                print("[DEBUG] do_screenshot: finally 调用，调度恢复按钮")
                # 无论如何都保证恢复按钮状态（优先通过线程安全信号）
                try:
                    self._sigobj.restore_screenshot.emit()
                except Exception:
                    # 回退到 QTimer 调度（如果信号不能使用）
                    def _restore():
                        try:
                            self.screenshot_btn.setEnabled(True)
                            self.screenshot_btn.setText("📷 截图")
                        except:
                            pass
                    QTimer.singleShot(0, _restore)
        
        thread = threading.Thread(target=do_screenshot, daemon=True)
        thread.start()
    
    def disconnect(self):
        """断开连接"""
        if self.stream_thread:
            # 发送停止流命令
            if hasattr(self.stream_thread, 'send_stop'):
                try:
                    self.stream_thread.send_stop()
                except:
                    pass
            self.stream_thread.stop()
            self.stream_thread.wait(2000)  # 等待线程结束，最多2秒
        
        if self.stream_socket:
            try:
                self.stream_socket.close()
            except:
                pass
            self.stream_socket = None
        
        if self.client:
            self.client.disconnect()
        
        self.status_label.setText("已断开连接")
        self.connection_info.setText("未连接")
        self.screen_label.clear()
        self.screen_label.setText("等待连接...")
        
        # 重新显示连接对话框
        self.show_connection_dialog()
    
    def closeEvent(self, event):
        """关闭事件"""
        if self.stream_thread:
            self.stream_thread.stop()
        if self.client:
            self.client.disconnect()
        event.accept()


class TerminalDialog(QDialog):
    """交互式终端对话框：展示来自服务器的输出并将按键作为原始字节发送到服务器。"""
    def __init__(self, client: RemoteControlClient, parent=None, title="远程终端"):
        super().__init__(parent)
        self.client = client
        self.setWindowTitle(title)
        self.resize(900, 600)

        layout = QVBoxLayout()
        self.setLayout(layout)

        self.term = QTextEdit()
        self.term.setReadOnly(True)
        self.term.setAcceptRichText(True)
        self.term.setStyleSheet("background-color:#000; color:#ddd; font-family: 'Consolas', monospace; font-size:13px;")
        layout.addWidget(self.term)

        # 保持焦点以接收键盘事件
        self.setFocusPolicy(Qt.StrongFocus)

    def closeEvent(self, event):
        # 关闭终端时尝试发送 EOF
        try:
            if self.client and self.client.connected:
                try:
                    self.client._send_encrypted(b"\x04")
                except:
                    pass
        finally:
            event.accept()

    def on_output_received(self, output_bytes, output_type):
        try:
            import html
            b = output_bytes

            def detect_decode(bb: bytes) -> str:
                try:
                    return bb.decode('utf-8')
                except Exception:
                    try:
                        return bb.decode('cp936')
                    except Exception:
                        return bb.decode('latin-1', errors='ignore')

            text = detect_decode(b)

            # 简化的 ANSI 到 HTML 转换（仅作展示）
            esc_re = re.compile(r'\x1b\[([0-9;]*)m')
            parts = esc_re.split(text)
            html_parts = []
            i = 0
            while i < len(parts):
                chunk = parts[i]
                if chunk:
                    html_parts.append(html.escape(chunk).replace('\n', '<br>'))
                if i + 1 < len(parts):
                    # 忽略具体样式，仅关闭/开span占位
                    params = parts[i + 1]
                    if params:
                        html_parts.append('<span>')
                        html_parts.append('</span>')
                i += 2

            html_content = ''.join(html_parts)
            QTimer.singleShot(0, lambda: self._append_html(html_content))
        except Exception:
            pass

    def _append_html(self, html_content: str):
        self.term.insertHtml(html_content)
        from PyQt5.QtGui import QTextCursor
        cursor = self.term.textCursor()
        cursor.movePosition(QTextCursor.End)
        self.term.setTextCursor(cursor)

    def keyPressEvent(self, event):
        if not self.client or not self.client.connected:
            return
        try:
            key = event.key()
            text = event.text()
            data = b''
            if text:
                data = text.encode('utf-8')
            else:
                if key == Qt.Key_Backspace:
                    data = b'\x7f'
                elif key in (Qt.Key_Return, Qt.Key_Enter):
                    data = b'\n'
                elif key == Qt.Key_Tab:
                    data = b'\t'
                elif key == Qt.Key_Left:
                    data = b'\x1b[D'
                elif key == Qt.Key_Right:
                    data = b'\x1b[C'
                elif key == Qt.Key_Up:
                    data = b'\x1b[A'
                elif key == Qt.Key_Down:
                    data = b'\x1b[B'
                else:
                    if event.modifiers() & Qt.ControlModifier:
                        if key == Qt.Key_C:
                            data = b'\x03'
                        elif key == Qt.Key_D:
                            data = b'\x04'
            if data:
                try:
                    self.client._send_encrypted(data)
                except Exception:
                    pass
        except Exception:
            pass


def main():
    """主函数"""
    if not PYQT_AVAILABLE:
        print("[-] 错误: 未安装PyQt5")
        print("[-] 请运行: pip install PyQt5")
        sys.exit(1)
    
    app = QApplication(sys.argv)
    window = RemoteControlGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == '__main__':
    main()

