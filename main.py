from fastapi import FastAPI, HTTPException, APIRouter, Request, Response, Path, Depends, UploadFile, File, Query, Form
from fastapi.responses import StreamingResponse, JSONResponse
from typing import Dict, List, Optional
from starlette.background import BackgroundTask
from pydantic import BaseModel
from typing import Optional
import os
import sys
import subprocess
import io
import ipaddress
import socket
import time
import uuid
import mimetypes
import tempfile
import datetime
import requests
import base64

app = FastAPI()
#router = APIRouter() # Use APIRouter() instead of FastAPI() in the future.

# Auth dependency
def verify_auth(request: Request):
    expected_token = os.getenv("TUESDAYS_HOUSE_API_KEY")
    auth_header = request.headers.get("Authorization")
    if not expected_token or auth_header != f"Bearer {expected_token}":
        raise HTTPException(status_code=401, detail="Unauthorized")

class TerminalCommand(BaseModel):
    command: str
    conversationId: str
    tmuxSession: Optional[str] = None
    decoderPipeline: Optional[str] = None
    interactive: Optional[bool] = False

class VoiceCallRequest(BaseModel):
    toNumber: str
    voiceScript: str
    mode: Optional[str] = "tts"

class MessageRequest(BaseModel):
    toNumber: str
    message: str
    mediaUrl: Optional[str] = None
    channelType: Optional[str] = "sms"

def run_popen_command(command: list[str]) -> Dict:
    start = time.time()
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    stdout, stderr = proc.communicate()
    end = time.time()
    return {
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "exit_code": proc.returncode,
        "execution_time": round(end - start, 4)
    }

def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False

def safe_serialize(obj, depth=0, max_depth=8):
    if depth > max_depth:
        return "<max depth reached>"

    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj

    if isinstance(obj, bytes):
        return obj.decode("utf-8", errors="replace")

    if isinstance(obj, (list, tuple)):
        return [safe_serialize(item, depth + 1, max_depth) for item in obj]

    if isinstance(obj, dict):
        return {
            safe_serialize(key, depth + 1, max_depth): safe_serialize(value, depth + 1, max_depth)
            for key, value in obj.items()
            if not callable(value)
        }

    # Fallback for non-serializable or weird types
    return repr(obj)

def minimal_scope(scope: dict) -> dict:
    return {
        "type": scope.get("type"),
        "http_version": scope.get("http_version"),
        "scheme": scope.get("scheme"),
        "method": scope.get("method"),
        #"client": scope.get("client"), # should probably stay private
        #"server": scope.get("server"), # also should be private, so these are commented out for now
        "root_path": scope.get("root_path"),
        "path": scope.get("path"),
        "raw_path": scope.get("raw_path"),
        "query_string": scope.get("query_string").decode("utf-8", errors="replace") if scope.get("query_string") else "",
        "headers": {
            k.decode("utf-8", errors="replace"): v.decode("utf-8", errors="replace") if k.decode("utf-8", errors="replace").lower() != "authorization" else "<redacted>"
            for k, v in scope.get("headers", [])
        }
    }

@app.post("/api/terminal")
async def exec_command(payload: TerminalCommand, _: None = Depends(verify_auth)):
    try:
        tmuxSession = "tuesdays-shared-session"

        if tmuxSession in payload and payload.tmuxSession and payload.tmuxSession != "":
            tmuxSession = payload.tmuxSession
        elif payload.conversationId is not None and payload.conversationId != "":
            tmuxSession = payload.conversationId

        try:
            # Create a real temporary script file
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".sh") as f:
                f.write("#!/bin/bash\n")
                f.write(f'THB_CMD_TIMESTAMP="$(date -Ins | xxd -p -c0)"\n')
                f.write(f'cd $HOME && source ~/.profile; tmux new-session -s "{tmuxSession}-$THB_CMD_TIMESTAMP" -d "bash -i -l"\n')
                f.write(f'tmux send-keys -t "{tmuxSession}-$THB_CMD_TIMESTAMP" "date" C-m\n')
                f.write(f'tmux send-keys -t "{tmuxSession}-$THB_CMD_TIMESTAMP" "cd $HOME && source ~/.profile" C-m\n')
                f.write(f'''tmux load-buffer -b "{tmuxSession}-$THB_CMD_TIMESTAMP" - <<'THBBASHCMDEOF'\nbash -i -l <<'THBBASHINNERCMDEOF'\n''')
                f.write(payload.command + "\n")
                f.write(f'''THBBASHINNERCMDEOF\n''')
                f.write(f'''echo $? > /tmp/tuesday-exitcode\n''')
                f.write(f'''THBBASHCMDEOF\n\n''')
                f.write(f'tmux paste-buffer -b "{tmuxSession}-$THB_CMD_TIMESTAMP" -t "{tmuxSession}-$THB_CMD_TIMESTAMP"\n')
                f.write(f'tmux send-keys -t "{tmuxSession}-$THB_CMD_TIMESTAMP" C-m\n')
                f.write(f'tmux delete-buffer -b "{tmuxSession}-$THB_CMD_TIMESTAMP"\n')
                f.write(f'tmux send-keys -t "{tmuxSession}-$THB_CMD_TIMESTAMP" "date" C-m\n')
                f.write(f'sleep 15 && tmux capture-pane -t "{tmuxSession}-$THB_CMD_TIMESTAMP" -pS -\n')
                f.write(f'\necho "tmuxSession was: \"{tmuxSession}-$THB_CMD_TIMESTAMP\""\n')

                script_path = f.name

            os.chmod(script_path, 0o750)

            # Run the script file
            proc = subprocess.Popen(
                ["/bin/bash", script_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            stdout, stderr = proc.communicate()

            # Read exit code
            exit_code = 1
            try:
                with open("/tmp/tuesday-exitcode") as f:
                    exit_code = int(f.read().strip())
            except:
                exit_code = proc.returncode

            # Prepare and return response in the exact same format
            return {
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
                "exitCode": exit_code,
                "metadata": {
                    "success": exit_code == 0,
                    "timestamp": datetime.datetime.utcnow().isoformat(),
                    "session": {"tmuxSession": tmuxSession or "default"},
                    "network": {}, "timing": {}
                }
            }

        except Exception as e:
            raise HTTPException(status_code=451, detail=str(e))
        finally:
            # Cleanup
            if os.path.exists(script_path):
                os.remove(script_path)
            if os.path.exists("/tmp/tuesday-exitcode"):
                os.remove("/tmp/tuesday-exitcode")

    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

@app.get("/api/files")
def list_files(_: None = Depends(verify_auth)):
    try:
        user_dir = os.getenv("HOST_USER_DIR", os.getenv("HOME"))

        # List all entries in the directory
        entries = os.listdir(user_dir)

        files = []

        # Iterate over each entry in the directory
        for entry in entries:
            entry_path = os.path.join(user_dir, entry)
            
            # Check if it's a symlink
            if os.path.islink(entry_path):
                symlink_target = os.readlink(entry_path)  # Get the target of the symlink
                files.append(f"{entry} -> {symlink_target}")
            else:
                # Use lstat to get more info, like if it's a directory or file
                stat_info = os.lstat(entry_path)
                if os.path.isdir(entry_path):
                    files.append(f"{entry}/")
                else:
                    files.append(f"{entry}")

        return {"files": files}
    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

# -----------------------------
# NEW: File download (GET)
# -----------------------------
@app.get("/api/file/download")
async def download_file(
    filepath: List[str] = Query(..., description="Filepath to download, relative or absolute."),
    _: None = Depends(verify_auth)
):
    try:
        if len(filepath) > 10:
            raise HTTPException(status_code=400, detail="You can request up to 1 file per download.")

        file_objs = []
        cleanup_tasks = []
        base_dir = os.getenv("HOST_USER_DIR", os.getenv("HOME"))

        # Collect all file-like objects to stream as parts
        for path in filepath:
            # If path is absolute, use as is; if relative, resolve from base_dir
            file_path = path if os.path.isabs(path) else os.path.abspath(os.path.join(base_dir, path))
            if not os.path.isfile(file_path):
                raise HTTPException(status_code=404, detail=f"File not found: {path}")
            size = os.path.getsize(file_path)
            if size > 10 * 1024 * 1024:
                raise HTTPException(status_code=400, detail=f"File too large (>10MB): {path}")

            f = open(file_path, "rb")
            file_objs.append((file_path, f, size))
            cleanup_tasks.append(lambda f=f: f.close())

        # Use a random boundary for multipart
        boundary = f"filepart-{uuid.uuid4().hex}"

        def filepart_iter():
            for path, f, size in file_objs:
                filename = os.path.basename(path)
                content_type, _ = mimetypes.guess_type(filename)
                if not content_type:
                    content_type = "application/octet-stream"
                    yield (
                    f"--{boundary}\r\n"
                    f'Content-Disposition: form-data; name="file"; filename="{filename}"; filepath="{path}"\r\n'
                    f"Content-Type: {content_type}\r\n"
                    f"Content-Length: {size}\r\n"
                    "\r\n"
                ).encode("utf-8")
                # Stream the file data
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    yield chunk
                yield b"\r\n"
            yield f"--{boundary}--\r\n"

        return StreamingResponse(
            filepart_iter(),
            media_type=f"multipart/form-data; boundary={boundary}",
            headers={"Cache-Control": "no-store"},
            background=BackgroundTask(lambda: [task() for task in cleanup_tasks])
        )

    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

# -----------------------------
# NEW: Multiple files download (GET)
# -----------------------------
@app.get("/api/files/download")
async def download_files(
    filepath: list[str] = Query(..., description="File path(s) to download (repeatable, up to 10)"),
    _: None = Depends(verify_auth)
):
    try:
        if not (1 <= len(filepath) <= 10):
            raise HTTPException(status_code=400, detail="You must request between 1 and 10 files per call.")

        openaiFileResponse = []
        base_dir = os.getenv("HOST_USER_DIR", os.getenv("HOME"))

        for path in filepath:
            # If path is absolute, use as is; if relative, resolve from base_dir
            file_path = path if os.path.isabs(path) else os.path.abspath(os.path.join(base_dir, path))
            if not os.path.isfile(file_path):
                raise HTTPException(status_code=404, detail=f"File not found: {path}")
            size = os.path.getsize(file_path)
            if size > 10 * 1024 * 1024:
                raise HTTPException(status_code=400, detail=f"File too large (>10MB): {path}")

            with open(file_path, "rb") as f:
                data = base64.b64encode(f.read()).decode("utf-8")
            name = os.path.basename(file_path)
            mime_type, _ = mimetypes.guess_type(name)
            openaiFileResponse.append({
                "name": name,
                "mime_type": mime_type or "application/octet-stream",
                "content": data
            })

        return JSONResponse({"openaiFileResponse": openaiFileResponse})

    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

# -----------------------------
# NEW: Multi-file upload (PUT)
# -----------------------------
@app.put("/api/files/upload")
async def upload_files(
    file: List[UploadFile] = File(..., description="Up to 10 files to upload."),
    filepaths: Optional[List[str]] = Form(None),
    _: None = Depends(verify_auth)
):
    try:
        if len(file) > 10:
            raise HTTPException(status_code=400, detail="You can upload up to 10 files at a time.")

        statuses = []
        for idx, upload in enumerate(file):
            # Determine path for this upload
            # Priority: filepaths[idx] (if provided), else use filename
            target_path = upload.filename
            if filepaths and len(filepaths) > idx:
                target_path = filepaths[idx]

            # Save to target path, streaming
            try:
                with open(target_path, "wb") as f:
                    while True:
                        chunk = await upload.read(8192)
                        if not chunk:
                            break
                        f.write(chunk)
                statuses.append({"filepath": target_path, "size": os.path.getsize(target_path), "status": "ok"})
            except Exception as e:
                statuses.append({"filepath": target_path, "status": "error", "error": str(e)})

        return {"uploaded": statuses}

    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

@app.post("/api/voice")
def make_voice_call(req: VoiceCallRequest, _: None = Depends(verify_auth)):
    try:
        payload = {
            "to": req.toNumber,
            "from": "+13435030418",
            "voice": {"type": req.mode, "source": req.voiceScript}
        }
        headers = {
            "Authorization": f"Bearer {os.getenv('OPENPHONE_API_KEY')}",
            "Content-Type": "application/json"
        }
        response = requests.post("https://api.openphone.com/v1/calls", json=payload, headers=headers)
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

@app.post("/api/message")
def send_message(req: MessageRequest, _: None = Depends(verify_auth)):
    try:
        payload = {
            "to": req.toNumber,
            "from": "+13435030418",
            "body": req.message
        }
        if req.mediaUrl:
            payload["media"] = [req.mediaUrl]
        headers = {
            "Authorization": f"Bearer {os.getenv('OPENPHONE_API_KEY')}",
            "Content-Type": "application/json"
        }
        response = requests.post("https://api.openphone.com/v1/messages", json=payload, headers=headers)
        return response.json()
    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))

@app.get("/api/net/scan")
async def net_scan(request: Request, _: None = Depends(verify_auth)):
    try:
        request_start = time.time()
        params = dict(request.query_params)
        target = params.get("target")


        # Sanitize and capture headers
        request_headers = {}
        for key, value in request.headers.items():
            if key.lower() == "authorization" and value.lower().startswith("bearer "):
                request_headers[key] = "Bearer <redacted>"
            else:
                request_headers[key] = value
        
        request_scope = safe_serialize(minimal_scope(request.scope))

        requester_ip = request.headers.get("X-Forwarded-For", request.client.host)
        resolved_ip = None
        resolved_host = None

        if target:
            if is_ip(target):
                resolved_ip = target
            else:
                try:
                    resolved_ip = socket.gethostbyname(target)
                except Exception as e:
                    raise HTTPException(status_code=400, detail=f"Cannot resolve target hostname: {e}")
        else:
            resolved_ip = requester_ip

        # Start subprocess command blocks
        nmap_result = run_popen_command(["bash", "-l", "-c", f"nmap --max-retries 1 --initial-rtt-timeout 50ms --max-rtt-timeout 50ms --exclude-ports 25 -T3 -Pn -sT {resolved_ip}"])
        traceroute_result = run_popen_command(["bash", "-l", "-c", f"traceroute -m 20 -A {resolved_ip}"])
        dig_rev_result = run_popen_command(["dig", "@8.8.8.8", "-x", resolved_ip, "+short"])
        whois_ip_result = run_popen_command(["whois", resolved_ip])
        rev_hostname = dig_rev_result["stdout"].strip().splitlines()[0] if dig_rev_result["stdout"] else None
        whois_revhost_result = run_popen_command(["whois", rev_hostname]) if rev_hostname else {
            "stdout": "",
            "stderr": "No hostname resolved from dig -x",
            "exit_code": 1,
            "execution_time": 0.0
        }

        request_end = time.time()

        return JSONResponse(content={
            "request_time": round(request_end - request_start, 4),
            "target": target or requester_ip,
            "resolved_ip": resolved_ip,
            "reverse_dns": dig_rev_result,
            "whois_ip": whois_ip_result,
            "whois_reverse_dns": whois_revhost_result,
            "nmap_scan": nmap_result,
            "traceroute": traceroute_result,
            "request_headers": request_headers,
            "request_scope": request_scope,
            "ip": requester_ip
        })

    except Exception as e:
        raise HTTPException(status_code=418, detail=str(e))
