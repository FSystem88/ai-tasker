import sys
import random
import asyncio
import aiohttp
import os
import subprocess
import re
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
                            QTextEdit, QPushButton, QLabel, QScrollArea, QCheckBox, QMessageBox, 
                            QProgressBar, QFileDialog)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor, QPalette
import logging
import shutil
import datetime

# Setup logging
logging.basicConfig(filename='app.log', level=logging.INFO, 
                    format='%(asctime)s - %(levelname)s - %(message)s')

class QueryThread(QThread):
    result = pyqtSignal(list)
    error = pyqtSignal(str)
    progress = pyqtSignal(str)

    def __init__(self, prompt, api_url, headers, user_input):
        super().__init__()
        self.prompt = prompt
        self.api_url = api_url
        self.headers = headers
        self.user_input = user_input

    async def query_ai(self, prompt):
        seed = random.randint(1, 999999999)
        async with aiohttp.ClientSession() as client:
            try:
                response = await client.get(
                    self.api_url.format(prompt, seed),
                    headers=self.headers,
                    timeout=600
                )
                text = await response.text()
                self.progress.emit(f"Raw AI response: {text[:1000] or 'Empty response'}")
                return text
            except Exception as e:
                self.error.emit(f"API Error: {str(e)}")
                return None

    async def get_command_for_task(self, task):
        prompt = f"Convert '{task}' to a valid Windows CMD command. Ensure the command is executable in Windows Command Prompt (cmd.exe) and does not use PowerShell or other shells. Return: Command: <command>"
        response = await self.query_ai(prompt)
        if response:
            self.progress.emit(f"Command response for '{task}': {response}")
            cmd_match = re.search(r'Command: (.+?)(?=\n\s*\*|$)', response, re.DOTALL)
            if cmd_match:
                return cmd_match.group(1).strip('`').strip()
        self.progress.emit(f"No command found for task: '{task}'")
        return "echo No command available"

    async def run_async(self):
        self.progress.emit(f"Sending request for: {self.user_input}")
        self.progress.emit(f"Prompt sent: {self.prompt}")
        response = await self.query_ai(self.prompt)
        if response:
            self.progress.emit(f"Tasks received: {response}")
            tasks = self.parse_tasks(response)
            valid_tasks = []
            for task in tasks:
                if not task['task'] or len(task['task']) < 3 or any(keyword in task['task'].lower() for keyword in ["press", "click", "type"]):
                    self.progress.emit(f"Skipping invalid task: '{task['task']}'")
                    continue
                command = await self.get_command_for_task(task['task'])
                if command == "echo No command available":
                    self.progress.emit(f"Skipping task with no valid command: '{task['task']}'")
                    continue
                task['command'] = command
                valid_tasks.append(task)
            if not valid_tasks:
                self.error.emit("No valid tasks found after filtering.")
            else:
                self.result.emit(valid_tasks)
        else:
            self.error.emit("Error getting AI response.")

    def parse_tasks(self, response):
        tasks = []
        pattern = r'- Task: ([^\n].{2,}?)(?:\n\s*Command: (.+?))?(?=\n-|\n\n|\n\s*\*|$)'  
        matches = re.findall(pattern, response, re.MULTILINE | re.DOTALL)
        for task, command in matches:
            task = task.strip()
            command = command.strip('`').strip() if command else ""
            if task and len(task) >= 3:
                tasks.append({"task": task, "command": command})
        return tasks

    def run(self):
        asyncio.run(self.run_async())

class WorkerThread(QThread):
    progress = pyqtSignal(str)
    error = pyqtSignal(str)
    finished = pyqtSignal(list)

    def __init__(self, tasks, selected_tasks, api_url, headers):
        super().__init__()
        self.tasks = tasks
        self.selected_tasks = selected_tasks
        self.api_url = api_url
        self.headers = headers
        self.executed_commands = []

    async def execute_command(self, command):
        self.progress.emit(f"Running command: {command}")
        if command == "echo No command available":
            return 0, "No command available", ""
        try:
            process = await asyncio.create_subprocess_shell(
                f'cmd.exe /c {command}', stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            stdout = stdout.decode('utf-8', errors='ignore')
            stderr = stderr.decode('utf-8', errors='ignore')
            return process.returncode, stdout, stderr
        except Exception as e:
            return -1, "", str(e)

    async def run_async(self):
        self.executed_commands = []
        for task in self.tasks:
            if task['task'] not in self.selected_tasks:
                self.progress.emit(f"Skipped task: {task['task']}")
                continue
            self.progress.emit(f"Running: {task['task']}")
            returncode, stdout, stderr = await self.execute_command(task['command'])
            if returncode == 0:
                self.progress.emit(f"Success: {stdout.strip() or 'No output'}")
                self.executed_commands.append({"task": task['task'], "command": task['command']})
            else:
                self.error.emit(f"Task failed '{task['task']}': {stderr.strip() or 'No error output'}")
                return
        self.finished.emit(self.executed_commands)

    def run(self):
        asyncio.run(self.run_async())

class ModernAIApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI Task Runner")
        self.setGeometry(100, 100, 900, 700)
        self.set_modern_style()
        self.init_ui()
        self.api_url = "https://text.pollinations.ai/{}?seed={}"
        self.headers = {}
        self.tasks = []
        self.undo_stack = []
        self.setup_logging()

    def setup_logging(self):
        self.log_area.setReadOnly(True)
        self.logger = logging.getLogger()
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
        self.logger.addHandler(handler)

    def set_modern_style(self):
        palette = QPalette()
        palette.setColor(QPalette.ColorRole.Window, QColor("#121212"))
        palette.setColor(QPalette.ColorRole.WindowText, QColor("#E0E0E0"))
        palette.setColor(QPalette.ColorRole.Base, QColor("#1E1E1E"))
        palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#2D2D2D"))
        palette.setColor(QPalette.ColorRole.Text, QColor("#E0E0E0"))
        palette.setColor(QPalette.ColorRole.Button, QColor("#0288D1"))
        palette.setColor(QPalette.ColorRole.ButtonText, QColor("#FFFFFF"))
        self.setPalette(palette)

        self.setStyleSheet("""
            QMainWindow, QWidget {
                background-color: #121212;
            }
            QTextEdit, QLineEdit {
                background-color: #1E1E1E;
                color: #E0E0E0;
                border: 1px solid #0288D1;
                border-radius: 8px;
                padding: 8px;
                font-size: 14px;
            }
            QPushButton {
                background-color: #0288D1;
                color: #FFFFFF;
                border: none;
                border-radius: 8px;
                padding: 10px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0277BD;
            }
            QPushButton:disabled {
                background-color: #455A64;
            }
            QCheckBox {
                color: #E0E0E0;
                font-size: 14px;
            }
            QProgressBar {
                border: 1px solid #0288D1;
                border-radius: 5px;
                text-align: center;
                color: #E0E0E0;
                background-color: #1E1E1E;
            }
            QProgressBar::chunk {
                background-color: #0288D1;
            }
            QLabel {
                color: #E0E0E0;
                font-size: 14px;
            }
        """)

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(10)
        layout.setContentsMargins(20, 20, 20, 20)

        title = QLabel("AI Task Runner")
        title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        self.input_text = QTextEdit()
        self.input_text.setPlaceholderText("Enter your request, e.g., 'Open Notepad' or 'Открыть Блокнот'")
        self.input_text.setFixedHeight(80)
        layout.addWidget(self.input_text)

        button_layout = QHBoxLayout()
        self.submit_button = QPushButton("Send Request")
        self.submit_button.clicked.connect(self.process_request)
        button_layout.addWidget(self.submit_button)

        self.execute_button = QPushButton("Run Tasks")
        self.execute_button.clicked.connect(self.execute_tasks)
        self.execute_button.setEnabled(False)
        button_layout.addWidget(self.execute_button)

        self.undo_button = QPushButton("Undo Actions")
        self.undo_button.clicked.connect(self.undo_actions)
        self.undo_button.setEnabled(False)
        button_layout.addWidget(self.undo_button)

        layout.addLayout(button_layout)

        self.task_scroll = QScrollArea()
        self.task_widget = QWidget()
        self.task_layout = QVBoxLayout(self.task_widget)
        self.task_scroll.setWidget(self.task_widget)
        self.task_scroll.setWidgetResizable(True)
        layout.addWidget(self.task_scroll)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

        self.log_area = QTextEdit()
        self.log_area.setFixedHeight(120)
        layout.addWidget(QLabel("Logs:"))
        layout.addWidget(self.log_area)

    def process_request(self):
        self.tasks = []
        self.task_layout.deleteLater()
        self.task_widget = QWidget()
        self.task_layout = QVBoxLayout(self.task_widget)
        self.task_scroll.setWidget(self.task_widget)
        self.execute_button.setEnabled(False)
        user_input = self.input_text.toPlainText().strip()
        if not user_input:
            QMessageBox.warning(self, "Error", "Enter a request!")
            return

        prompt = f"Convert '{user_input}' to a valid Windows CMD command. Ensure the command is executable in Windows Command Prompt (cmd.exe) and does not use PowerShell or other shells. Return: - Task: <task>\n  Command: <command>"
        self.query_thread = QueryThread(prompt, self.api_url, self.headers, user_input)
        self.query_thread.result.connect(self.handle_query_result)
        self.query_thread.error.connect(self.handle_query_error)
        self.query_thread.progress.connect(self.log_area.append)
        self.query_thread.start()
        self.submit_button.setEnabled(False)
        self.log_area.append("Waiting for AI response...")

    def handle_query_result(self, tasks):
        self.tasks = tasks
        if self.tasks:
            self.task_checkboxes = []
            for task in self.tasks:
                checkbox = QCheckBox(f"{task['task']} (Command: {task['command']})")
                checkbox.setChecked(True)
                self.task_checkboxes.append(checkbox)
                self.task_layout.addWidget(checkbox)
            self.execute_button.setEnabled(True)
            self.log_area.append("Tasks received successfully.")
            logging.info("Tasks received successfully")
        else:
            self.log_area.append("No valid tasks received from AI.")
            logging.warning("No valid tasks received")
        self.submit_button.setEnabled(True)

    def handle_query_error(self, error):
        self.log_area.append(error)
        logging.error(error)
        self.submit_button.setEnabled(True)

    def execute_tasks(self):
        selected_tasks = [checkbox.text().split(" (Command:")[0] for checkbox in self.task_checkboxes if checkbox.isChecked()]
        if not selected_tasks:
            QMessageBox.warning(self, "Error", "Select at least one task!")
            return

        self.progress_bar.setMaximum(len(selected_tasks))
        self.progress_bar.setValue(0)
        self.worker = WorkerThread(self.tasks, selected_tasks, self.api_url, self.headers)
        self.worker.progress.connect(self.update_progress)
        self.worker.error.connect(self.handle_error)
        self.worker.finished.connect(self.handle_finish)
        self.worker.start()

    def update_progress(self, message):
        self.log_area.append(message)
        logging.info(message)
        self.progress_bar.setValue(self.progress_bar.value() + 1)

    def handle_error(self, error_message):
        self.log_area.append(error_message)
        logging.error(error_message)
        reply = QMessageBox.question(
            self, "Error",
            f"{error_message}\nUndo completed actions?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            self.undo_actions()
        self.progress_bar.setValue(0)
        self.undo_button.setEnabled(len(self.undo_stack) > 0)

    def handle_finish(self, executed_commands):
        self.undo_stack.extend(executed_commands)
        self.log_area.append("All tasks completed successfully.")
        logging.info("All tasks completed successfully")
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.undo_button.setEnabled(True)

    def undo_actions(self):
        for task in reversed(self.undo_stack):
            undo_prompt = f"For the command '{task['command']}', write a Windows CMD command to undo it. Ensure the command is executable in Windows Command Prompt (cmd.exe) and does not use PowerShell or other shells. Return: Command: <undo command>"
            response = asyncio.run(self.query_ai(undo_prompt))
            if response:
                cmd_match = re.search(r'Command: (.+?)(?:$|\n)', response, re.DOTALL)
                if cmd_match:
                    undo_command = cmd_match.group(1).strip('`').strip()
                    if undo_command == "echo No undo available":
                        self.log_area.append(f"No undo for task: {task['task']}")
                        logging.info(f"No undo for task: {task['task']}")
                        continue
                    try:
                        result = subprocess.run(f'cmd.exe /c {undo_command}', shell=True, capture_output=True, text=True)
                        self.log_area.append(f"Undo: {undo_command}\nOutput: {result.stdout.strip() or 'No output'}")
                        logging.info(f"Undo: {undo_command}\nOutput: {result.stdout}")
                        if result.stderr:
                            self.log_area.append(f"Undo error: {result.stderr.strip() or 'No error output'}")
                            logging.error(f"Undo error: {result.stderr}")
                    except Exception as e:
                        self.log_area.append(f"Error running undo: {str(e)}")
                        logging.error(f"Error running undo: {str(e)}")
        self.undo_stack.clear()
        self.undo_button.setEnabled(False)
        self.log_area.append("All actions undone.")
        logging.info("All actions undone")

    def save_history(self):
        with open("history.txt", "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now()}: {self.input_text.toPlainText()}\n")
        self.log_area.append("Request saved to history.")

    def load_history(self):
        try:
            with open("history.txt", "r", encoding="utf-8") as f:
                lines = f.readlines()
                if lines:
                    self.input_text.setPlainText(lines[-1].split(": ", 1)[1])
                    self.log_area.append("Loaded last request from history.")
        except Exception as e:
            self.log_area.append(f"Error loading history: {str(e)}")

    def export_log(self):
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Log", 
                                                  os.path.join(os.path.expanduser("~"), "Desktop", "log.txt"), 
                                                  "Text Files (*.txt)")
        if file_path:
            try:
                shutil.copy("app.log", file_path)
                self.log_area.append(f"Log exported: {file_path}")
            except Exception as e:
                self.log_area.append(f"Error exporting log: {str(e)}")

    def clear_log(self):
        self.log_area.clear()
        self.log_area.append("Logs cleared.")
        logging.info("Logs cleared")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ModernAIApp()
    window.show()
    sys.exit(app.exec())