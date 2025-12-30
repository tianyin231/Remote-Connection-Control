"""
远程控制软件 - 被控端（服务端）
监听来自控制端的连接，接收并执行命令
"""
import socket
import subprocess
import threading
import sys
import io
import struct
import time
import hashlib
import getpass
import os
import select
try:
    import pty
    PTY_AVAILABLE = True
except Exception:
    PTY_AVAILABLE = False
try:
    from PIL import Image
    import mss
    SCREENSHOT_AVAILABLE = True
except ImportError:
    SCREENSHOT_AVAILABLE = False
    print("[!] 警告: 未安装截图库，画面传输功能不可用")
    print("[!] 请运行: pip install pillow mss")

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
    print("[!] 请运行: pip install cryptography")


class RemoteControlServer:
    def __init__(self, host='0.0.0.0', port=8888, secret_key=None):
        self.host = host
        self.port = port
        self.socket = None
        self.running = False
        self.secret_key = secret_key
        self.fernet = None
        
        # 如果提供了密钥，生成Fernet加密对象
        if self.secret_key and ENCRYPTION_AVAILABLE:
            self._setup_encryption()
    
    def _setup_encryption(self):
        """设置加密"""
        if not ENCRYPTION_AVAILABLE:
            return False
        
        try:
            # 使用PBKDF2从密钥派生Fernet密钥
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b'remote_control_salt',  # 固定salt（实际应用中应随机生成）
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.secret_key.encode('utf-8')))
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
            decrypted = self.fernet.decrypt(data)
            return decrypted
        except Exception as e:
            print(f"[-] 解密失败: {e}")
            return data
    
    def _send_encrypted(self, client_socket, data):
        """发送加密数据（支持字符串和字节）"""
        if isinstance(data, str):
            data = data.encode('utf-8')
        
        # 如果启用了加密，则加密数据
        if self.fernet:
            encrypted_data = self._encrypt_data(data)
        else:
            encrypted_data = data
        
        size = len(encrypted_data)
        client_socket.sendall(struct.pack('!I', size))
        client_socket.sendall(encrypted_data)
    
    def _recv_encrypted(self, client_socket):
        """接收并解密数据"""
        # 先接收大小
        size_data = b""
        while len(size_data) < 4:
            chunk = client_socket.recv(4 - len(size_data))
            if not chunk:
                return None
            size_data += chunk
        
        size = struct.unpack('!I', size_data)[0]
        
        # 接收数据
        data = b""
        while len(data) < size:
            chunk = client_socket.recv(min(4096, size - len(data)))
            if not chunk:
                return None
            data += chunk
        
        # 如果启用了加密，则解密数据
        if self.fernet:
            decrypted_data = self._decrypt_data(data)
        else:
            decrypted_data = data
        
        return decrypted_data

    def start(self):
        """启动服务器"""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            self.running = True
            
            print(f"[*] 服务器启动成功")
            print(f"[*] 监听地址: {self.host}:{self.port}")
            
            # 获取本机所有IP地址用于显示
            if self.host == '0.0.0.0':
                print(f"[*] 本机IP地址列表:")
                try:
                    import socket as sock
                    hostname = sock.gethostname()
                    # 获取主机名对应的IP
                    try:
                        local_ip = sock.gethostbyname(hostname)
                        print(f"    - {local_ip}:{self.port} (主机名: {hostname})")
                    except:
                        pass
                    
                    # 获取所有网络接口的IP地址
                    import subprocess
                    if sys.platform == 'win32':
                        # Windows系统
                        result = subprocess.run(['ipconfig'], capture_output=True, text=True, timeout=2)
                        if result.returncode == 0:
                            lines = result.stdout.split('\n')
                            for i, line in enumerate(lines):
                                if 'IPv4' in line or 'IP Address' in line:
                                    ip_line = line.split(':')[-1].strip()
                                    if ip_line and ip_line != '0.0.0.0':
                                        print(f"    - {ip_line}:{self.port}")
                    else:
                        # Linux/Mac系统
                        result = subprocess.run(['hostname', '-I'], capture_output=True, text=True, timeout=2)
                        if result.returncode == 0:
                            ips = result.stdout.strip().split()
                            for ip in ips:
                                if ip and ip != '0.0.0.0':
                                    print(f"    - {ip}:{self.port}")
                except:
                    pass
                print(f"[*] 控制端可使用以上任一IP地址连接")
            print("[*] 等待控制端连接...")
            
            while self.running:
                try:
                    client_socket, address = self.socket.accept()
                    print(f"[+] 新的连接来自: {address[0]}:{address[1]}")
                    
                    # 为每个客户端创建新线程
                    client_thread = threading.Thread(
                        target=self.handle_client,
                        args=(client_socket, address)
                    )
                    client_thread.daemon = True
                    client_thread.start()
                except Exception as e:
                    if self.running:
                        print(f"[-] 接受连接时出错: {e}")
        except Exception as e:
            print(f"[-] 服务器启动失败: {e}")
        finally:
            self.stop()

    def stream_screen(self, client_socket, fps=5, quality=50, scale=0.5):
        """持续发送屏幕截图流"""
        if not SCREENSHOT_AVAILABLE:
            try:
                self._send_encrypted(client_socket, "ERROR:截图功能不可用")
            except:
                pass
            return
        
        print(f"[*] 开始实时画面传输 (FPS: {fps}, 质量: {quality}, 缩放: {scale})")
        frame_time = 1.0 / fps
        
        try:
            with mss.mss() as sct:
                monitor = sct.monitors[1]
                
                while self.running:
                    try:
                        start_time = time.time()
                        
                        # 捕获屏幕
                        screenshot = sct.grab(monitor)
                        # 使用更兼容的属性和模式：优先使用 screenshot.rgb
                        try:
                            raw_bytes = screenshot.rgb
                            img = Image.frombytes("RGB", screenshot.size, raw_bytes)
                        except Exception:
                            # 回退到 bgra -> RGB 处理
                            try:
                                raw_bytes = screenshot.bgra
                                img = Image.frombytes("RGB", screenshot.size, raw_bytes, "raw", "BGRX")
                            except Exception:
                                raise
                        
                        # 缩放处理
                        if scale != 1.0:
                            new_size = (int(img.width * scale), int(img.height * scale))
                            # Pillow 版本兼容性处理
                            try:
                                resample = Image.Resampling.LANCZOS
                            except Exception:
                                resample = Image.LANCZOS
                            img = img.resize(new_size, resample)
                        
                        # 压缩为JPEG
                        buffer = io.BytesIO()
                        img.save(buffer, format='JPEG', quality=quality, optimize=True)
                        image_data = buffer.getvalue()
                        
                        # 加密并发送图片数据（使用统一的发送方法）
                        try:
                            self._send_encrypted(client_socket, image_data)
                        except Exception:
                            print("[-] 发送画面数据失败，停止流传输")
                            break
                        
                        # 控制帧率
                        elapsed = time.time() - start_time
                        sleep_time = max(0, frame_time - elapsed)
                        if sleep_time > 0:
                            time.sleep(sleep_time)
                            
                    except Exception as e:
                        print(f"[-] 画面传输出错: {e}")
                        break
        except Exception as e:
            print(f"[-] 画面流传输失败: {e}")
        finally:
            print("[*] 实时画面传输已停止")

    def _authenticate_client(self, client_socket):
        """验证客户端密钥"""
        if not self.secret_key:
            # 没有设置密钥，直接通过（发送未加密的OK）
            try:
                ok_msg = "OK".encode('utf-8')
                client_socket.sendall(struct.pack('!I', len(ok_msg)))
                client_socket.sendall(ok_msg)
            except:
                pass
            return True
        
        try:
            # 发送认证请求（未加密，因为此时还没有密钥）
            auth_req = "AUTH_REQUIRED".encode('utf-8')
            client_socket.sendall(struct.pack('!I', len(auth_req)))
            client_socket.sendall(auth_req)
            
            # 接收客户端密钥（可能是加密的，也可能未加密）
            size_data = b""
            while len(size_data) < 4:
                chunk = client_socket.recv(4 - len(size_data))
                if not chunk:
                    return False
                size_data += chunk
            
            size = struct.unpack('!I', size_data)[0]
            client_key_data = b""
            while len(client_key_data) < size:
                chunk = client_socket.recv(min(4096, size - len(client_key_data)))
                if not chunk:
                    return False
                client_key_data += chunk
            
            # 尝试解密（如果客户端使用了加密）
            try:
                if self.fernet:
                    client_key = self._decrypt_data(client_key_data).decode('utf-8', errors='ignore')
                else:
                    client_key = client_key_data.decode('utf-8', errors='ignore')
            except:
                # 解密失败，可能是未加密的
                client_key = client_key_data.decode('utf-8', errors='ignore')
            
            # 检查是否是已认证标记（画面流连接复用主连接认证）
            if client_key == "AUTH_ALREADY_AUTHENTICATED":
                # 客户端已经通过主连接认证，直接通过
                if not self.fernet:
                    self._setup_encryption()
                self._send_encrypted(client_socket, "AUTH_SUCCESS")
                print(f"[+] 画面流连接认证成功（复用主连接认证）")
                return True
            
            # 验证密钥
            if client_key == self.secret_key:
                # 确保加密已设置
                if not self.fernet:
                    self._setup_encryption()
                # 发送认证成功（加密）
                self._send_encrypted(client_socket, "AUTH_SUCCESS")
                print(f"[+] 客户端认证成功")
                return True
            else:
                # 发送认证失败（未加密）
                fail_msg = "AUTH_FAILED".encode('utf-8')
                client_socket.sendall(struct.pack('!I', len(fail_msg)))
                client_socket.sendall(fail_msg)
                print(f"[-] 客户端认证失败: 密钥错误")
                return False
        except Exception as e:
            print(f"[-] 认证过程出错: {e}")
            import traceback
            traceback.print_exc()
            return False

    def _handle_pty_session(self, client_socket, command):
        """在当前连接上运行伪终端（PTY/ConPTY），并桥接 socket <-> pty master。
        该方法阻塞直到会话结束。"""
        # 仅支持类 Unix 使用 pty; Windows 用户请安装 pywinpty/ConPTY 支持
        if sys.platform == 'win32' and not PTY_AVAILABLE:
            try:
                self._send_encrypted(client_socket, "ERROR: 服务器未启用 ConPTY 支持，请在服务端安装 pywinpty")
            except:
                pass
            return

        try:
            if sys.platform == 'win32':
                # 尝试使用 conpty via subprocess with creationflags CREATE_NEW_CONSOLE is not sufficient.
                # We expect pywinpty to be installed for Windows support. If not available, return error above.
                pass

            # 使用 pty.openpty 创建伪终端
            master_fd, slave_fd = pty.openpty()

            # 启动子进程，绑定 slave 到 stdio
            proc = subprocess.Popen(
                command,
                shell=True,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            os.close(slave_fd)

            # 通知客户端 PTY 已启动
            try:
                self._send_encrypted(client_socket, "PTY_START")
            except:
                pass

            # 尝试将 master 设为非阻塞
            try:
                import fcntl
                orig_flags = fcntl.fcntl(master_fd, fcntl.F_GETFL)
                fcntl.fcntl(master_fd, fcntl.F_SETFL, orig_flags | os.O_NONBLOCK)
            except Exception:
                pass

            # 桥接循环
            while True:
                rlist, _, _ = select.select([client_socket, master_fd], [], [])
                if master_fd in rlist:
                    try:
                        data = os.read(master_fd, 4096)
                    except OSError:
                        break
                    if not data:
                        break
                    try:
                        self._send_encrypted(client_socket, data)
                    except:
                        break

                if client_socket in rlist:
                    incoming = self._recv_encrypted(client_socket)
                    if not incoming:
                        break
                    try:
                        os.write(master_fd, incoming)
                    except OSError:
                        break

            try:
                proc.terminate()
            except:
                pass
            try:
                os.close(master_fd)
            except:
                pass

        except Exception as e:
            try:
                self._send_encrypted(client_socket, f"ERROR: PTY 会话启动失败: {e}")
            except:
                pass
            return

    def _run_command_in_pty(self, command, timeout=30):
        """在临时 pty 中运行命令并返回收集到的输出字节。"""
        try:
            master_fd, slave_fd = pty.openpty()
            proc = subprocess.Popen(
                command,
                shell=True,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                preexec_fn=os.setsid if hasattr(os, 'setsid') else None
            )
            os.close(slave_fd)

            output = bytearray()
            start_time = time.time()
            try:
                # 读取直到进程结束或超时
                while True:
                    rlist, _, _ = select.select([master_fd], [], [], 0.1)
                    if master_fd in rlist:
                        try:
                            chunk = os.read(master_fd, 4096)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output.extend(chunk)
                    # 检查进程是否结束
                    if proc.poll() is not None:
                        # 读取剩余数据
                        try:
                            while True:
                                chunk = os.read(master_fd, 4096)
                                if not chunk:
                                    break
                                output.extend(chunk)
                        except Exception:
                            pass
                        break
                    if timeout and (time.time() - start_time) > timeout:
                        try:
                            proc.terminate()
                        except:
                            pass
                        break
            finally:
                try:
                    os.close(master_fd)
                except:
                    pass
                try:
                    proc.kill()
                except:
                    pass

            return bytes(output)
        except Exception as e:
            return f"ERROR: 通过PTY运行命令失败: {e}".encode('utf-8')
    
    def handle_client(self, client_socket, address):
        """处理客户端连接"""
        streaming = False
        stream_thread = None
        shell_process = None
        shell_running = False
        
        try:
            # 设置socket超时，避免长时间阻塞
            client_socket.settimeout(300)  # 5分钟超时
            
            # 首先进行身份验证
            if not self._authenticate_client(client_socket):
                print(f"[-] 客户端 {address[0]}:{address[1]} 认证失败，断开连接")
                client_socket.close()
                return
            
            print(f"[+] 客户端 {address[0]}:{address[1]} 认证成功，开始处理命令")

            # 我们不再使用基于管道的旧方法；所有命令均尽可能在 PTY 中执行
            streaming = False
            stream_thread = None
            
            while self.running:
                # 接收命令（加密）
                try:
                    encrypted_data = self._recv_encrypted(client_socket)
                    if not encrypted_data:
                        break
                    
                    command = encrypted_data.decode('utf-8', errors='ignore').strip()
                except socket.timeout:
                    # 超时后继续循环，保持连接
                    continue
                except Exception as e:
                    print(f"[-] 接收命令时出错: {e}")
                    break
                
                if not command:
                    continue
                
                if not command:
                    continue
                
                print(f"[*] 收到命令: {command}")
                
                # 特殊命令处理
                if command.lower() == 'exit' or command.lower() == 'quit':
                    # 关闭 shell 进程
                    shell_running = False
                    if shell_process:
                        try:
                            shell_process.stdin.close()
                            shell_process.terminate()
                            shell_process.wait(timeout=2)
                        except:
                            try:
                                shell_process.kill()
                            except:
                                pass
                    response = "连接已关闭"
                    try:
                        self._send_encrypted(client_socket, response)
                    except:
                        pass
                    break
                
                # 停止实时流
                if command.lower() == 'stop_stream':
                    streaming = False
                    response = "已停止画面流"
                    try:
                        self._send_encrypted(client_socket, response)
                    except:
                        pass
                    continue
                
                # 实时画面流命令
                if command.lower().startswith('stream'):
                    if streaming:
                        response = "画面流已在运行中"
                        try:
                            self._send_encrypted(client_socket, response)
                        except:
                            pass
                        continue
                    
                    # 解析参数
                    fps = 5
                    quality = 50
                    scale = 0.5
                    
                    if ' ' in command:
                        parts = command.split()
                        for i, part in enumerate(parts):
                            if part == '-fps' and i + 1 < len(parts):
                                fps = int(parts[i + 1])
                            elif part == '-q' and i + 1 < len(parts):
                                quality = int(parts[i + 1])
                            elif part == '-s' and i + 1 < len(parts):
                                scale = float(parts[i + 1])
                    
                    # 启动流传输线程
                    streaming = True
                    stream_thread = threading.Thread(
                        target=self.stream_screen,
                        args=(client_socket, fps, quality, scale),
                        daemon=True
                    )
                    stream_thread.start()
                    continue
                
                # 截图命令处理
                if command.lower() == 'screenshot' or command.lower().startswith('screenshot'):
                    if SCREENSHOT_AVAILABLE:
                        try:
                            # 解析参数（可选：质量、缩放）
                            quality = 70
                            scale = 1.0
                            if ' ' in command:
                                parts = command.split()
                                for i, part in enumerate(parts):
                                    if part == '-q' and i + 1 < len(parts):
                                        quality = int(parts[i + 1])
                                    elif part == '-s' and i + 1 < len(parts):
                                        scale = float(parts[i + 1])
                            
                            # 捕获屏幕
                            with mss.mss() as sct:
                                # 获取主显示器
                                monitor = sct.monitors[1]  # 0是所有显示器，1是主显示器
                                screenshot = sct.grab(monitor)
                                
                                # 转换为PIL Image
                                img = Image.frombytes("RGB", screenshot.size, screenshot.bgra, "raw", "BGRX")
                                
                                # 缩放处理
                                if scale != 1.0:
                                    new_size = (int(img.width * scale), int(img.height * scale))
                                    img = img.resize(new_size, Image.Resampling.LANCZOS)
                                
                                # 压缩为JPEG
                                buffer = io.BytesIO()
                                img.save(buffer, format='JPEG', quality=quality, optimize=True)
                                image_data = buffer.getvalue()
                            
                                # 统一使用 _send_encrypted 发送图片数据（会处理加密与长度前缀）
                                try:
                                    self._send_encrypted(client_socket, image_data)
                                    print(f"[*] 已发送截图 ({len(image_data)} 字节)")
                                except Exception as e:
                                    print(f"[-] 发送截图失败: {e}")
                                continue
                        except Exception as e:
                            error_msg = f"截图失败: {str(e)}"
                            try:
                                self._send_encrypted(client_socket, error_msg)
                            except:
                                pass
                            print(f"[-] {error_msg}")
                            continue
                    else:
                        error_msg = "截图功能不可用: 请安装 pillow 和 mss 库"
                        try:
                            self._send_encrypted(client_socket, error_msg)
                        except:
                            pass
                        continue
                
                # 执行命令 - 使用 PTY 运行以获得真实终端行为（或回退到 subprocess）
                try:
                    # 先尝试将命令作为普通字符串解码
                    decoded_cmd = None
                    try:
                        decoded_cmd = encrypted_data.decode('utf-8', errors='ignore').strip()
                    except Exception:
                        decoded_cmd = None

                    if decoded_cmd:
                        # 如果以 pty: 开头，应由 _handle_pty_session 处理（交互式会话）
                        if decoded_cmd.lower().startswith('pty:'):
                            pty_cmd = decoded_cmd[len('pty:'):]
                            self._handle_pty_session(client_socket, pty_cmd)
                            continue

                        # 其他文本命令，优先在 PTY 中执行以保留终端效果
                        if PTY_AVAILABLE:
                            out_bytes = self._run_command_in_pty(decoded_cmd)
                            try:
                                self._send_encrypted(client_socket, out_bytes)
                            except:
                                break
                            continue
                        else:
                            # 回退到 subprocess.run
                            try:
                                completed = subprocess.run(decoded_cmd, shell=True, capture_output=True, timeout=60)
                                out = completed.stdout + completed.stderr
                                if not out:
                                    out = b"\n"
                                self._send_encrypted(client_socket, out)
                            except Exception as e:
                                try:
                                    self._send_encrypted(client_socket, f"ERROR: {e}".encode('utf-8'))
                                except:
                                    pass
                            continue

                    # 如果接收到的是二进制或无法解码的数据，忽略或回显错误
                    try:
                        self._send_encrypted(client_socket, b"ERROR: no mingling")
                    except:
                        break
                except Exception as e:
                    print(f"[-] 执行命令时出错: {e}")
                    try:
                        error_response = f"错误: 执行命令时出错 - {str(e)}"
                        self._send_encrypted(client_socket, error_response.encode('utf-8'))
                    except:
                        break
                    
        except Exception as e:
            print(f"[-] 处理客户端 {address} 时出错: {e}")
            import traceback
            traceback.print_exc()
        finally:
            # 关闭 shell 进程
            shell_running = False
            if shell_process:
                try:
                    shell_process.stdin.close()
                    shell_process.terminate()
                    shell_process.wait(timeout=2)
                except:
                    try:
                        shell_process.kill()
                    except:
                        pass
            client_socket.close()
            print(f"[-] 客户端 {address[0]}:{address[1]} 已断开连接")

    def stop(self):
        """停止服务器"""
        self.running = False
        if self.socket:
            self.socket.close()
        print("[*] 服务器已停止")


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(description='远程控制软件 - 被控端')
    parser.add_argument('-H', '--host', default='0.0.0.0', help='监听地址 (默认: 0.0.0.0)')
    parser.add_argument('-p', '--port', type=int, default=8888, help='监听端口 (默认: 8888)')
    parser.add_argument('-k', '--key', help='连接密钥（如未提供，将提示输入）')
    
    args = parser.parse_args()
    
    # 获取密钥
    secret_key = args.key
    if not secret_key:
        if ENCRYPTION_AVAILABLE:
            secret_key = getpass.getpass("请输入连接密钥（留空则不启用加密）: ").strip()
            if not secret_key:
                print("[*] 未设置密钥，将不启用加密和验证")
                secret_key = None
        else:
            print("[!] 警告: 未安装加密库，无法启用密钥验证")
            secret_key = None
    
    server = RemoteControlServer(host=args.host, port=args.port, secret_key=secret_key)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\n[*] 收到中断信号，正在关闭服务器...")
        server.stop()
        sys.exit(0)


if __name__ == '__main__':
    main()

