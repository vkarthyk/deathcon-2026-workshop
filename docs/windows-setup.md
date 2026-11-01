# Windows setup: native PowerShell or WSL2

Use **native PowerShell** on Windows, including inside an existing DEATHCon Windows VM. No WSL or nested virtualization is required for this path. If you already use WSL2 on your host, the alternative instructions below remain available. `setup.ps1` is the native launcher; `setup.sh` is for macOS/Linux/WSL.

No Windows VM, Active Directory domain join, Sysmon or Sentinel is needed for this workshop. Tailscale is needed only if the event's download server or CTF submission platform requires private-network access. Follow the organizers' access instructions if so; it is not a runtime dependency of these exercises.

## Recommended inside a Windows VM: native PowerShell

### Install Python and extract the download

Install **64-bit Python 3.10+ (3.11 recommended)** from [python.org](https://www.python.org/downloads/windows/). Include the Python launcher; a per-user installation is sufficient. Reopen PowerShell after installation and check:

```powershell
py -3 --version
```

Download `workshop-student.zip`, right-click it in File Explorer and select **Extract All**. Use a writable local folder such as `C:\workshops\workshop-student`, outside OneDrive or a shared network drive. Do not reuse a `.workshop-venv` from Linux or another machine.

### Start the workshop

Open **ordinary PowerShell** in the extracted folder (administrative privileges are not required):

```powershell
cd C:\workshops\workshop-student
Unblock-File .\setup.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\setup.ps1
```

Review the downloaded script before unblocking it. `RemoteSigned` applies only to this launched PowerShell process; it does not change the machine-wide execution policy. If organizational policy blocks scripts or package installation, contact IT or the event organizers rather than changing enforced policy.

The script finds Python, creates `.workshop-venv\Scripts\python.exe`, installs dependencies and registers the workshop kernel, then opens notebook 00. No virtual-environment activation is needed. Keep PowerShell open and use the printed localhost URL in the browser **inside the Windows VM**. Internet access is needed for initial Python package installation. Tailscale/domain membership does not replace these dependencies.

Options:

```powershell
# Another Jupyter port:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\setup.ps1 -Port 8889

# Install dependencies without launching Jupyter:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\setup.ps1 -PrepareOnly

# Choose an installed Python executable explicitly:
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\setup.ps1 -Python 'C:\Python311\python.exe'
```

### Native Windows CTF and optional model

Extract the CTF ZIPs into `C:\workshops\ctf` so that it contains `easy` and `hard`. From the workshop folder, launch them with:

```powershell
.\.workshop-venv\Scripts\python.exe -m jupyterlab --notebook-dir=C:\workshops\ctf
```

Select the workshop Python kernel and open either `Start.ipynb`.

For the optional AI exercise, install **Ollama for Windows** from [ollama.com/download/windows](https://ollama.com/download/windows), start the application **inside the same Windows system/VM as Jupyter**, reopen PowerShell and run:

```powershell
ollama pull qwen3:8b
ollama list
```

Then follow notebook 04. No Linux installer or `zstd` is required for native Windows Ollama. A model on your host is not automatically the VM's localhost endpoint. The core workshop and CTFs do not need a model; a small Windows VM may have insufficient RAM or GPU access for the optional extension. Do not allocate all host memory to the VM.

## Alternative: WSL2 on your Windows host

WSL2 inside an existing Windows VM requires nested virtualization and may not be available. Use the native PowerShell path above inside the DEATHCon VM. The following is for students who prefer Ubuntu on a Windows host with WSL2 support.

## 1. Install WSL2

On Windows 11 or a supported, updated Windows 10 installation, open **PowerShell as Administrator** and run:

```powershell
wsl --install -d Ubuntu
```

Restart Windows if prompted. Open **Ubuntu** from the Start menu and complete its first-run setup, choosing a Linux username and password. This account is local to your Ubuntu installation; it is not your Windows or DEATHCon account. Linux password entry does not display characters.

If WSL is already installed, check its version in PowerShell:

```powershell
wsl --list --verbose
```

Ubuntu should show version `2`. If it shows version `1`, convert the distribution using its exact name from that list:

```powershell
wsl --set-version Ubuntu 2
```

If installation reports virtualization is unavailable, follow [Microsoft's WSL installation guide](https://learn.microsoft.com/windows/wsl/install). Managed devices may require IT assistance to enable WSL or virtualization.

## 2. Install Linux prerequisites

Run the remaining shell commands in the **Ubuntu terminal**, not PowerShell:

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip unzip git curl zstd
python3 --version
```

Python must be 3.10 or newer. A current Ubuntu release provides a suitable version. `zstd` is included for the optional Ollama installer.

## 3. Extract the student download

Download `workshop-student.zip` with your Windows browser. Keep the extracted working directory in Ubuntu's home directory to avoid Windows filesystem overhead and OneDrive synchronization.

Replace `YOUR_WINDOWS_USER` below with the Windows profile folder containing your Downloads directory; it can differ from your Ubuntu username. Adjust the path if your browser saved elsewhere.

```bash
mkdir -p ~/workshops
unzip "/mnt/c/Users/YOUR_WINDOWS_USER/Downloads/workshop-student.zip" -d ~/workshops
cd ~/workshops/workshop-student
bash setup.sh
```

For the source-repository edition instead of a student ZIP:

```bash
mkdir -p ~/workshops
cd ~/workshops
git clone https://github.com/ved-k_data/k8s-ocsf-workshop.git
cd k8s-ocsf-workshop
bash setup.sh
```

Choose one path; you do not need both copies. The repository edition also contains facilitator/organizer material, while the student ZIP contains clean exercises.

## 4. Open and check Jupyter

Copy the complete token-bearing URL printed by setup, usually starting with `http://localhost:8888/`, into Edge, Chrome or Firefox on Windows. A browser may not open automatically from WSL. Keep the Ubuntu terminal running.

Open `notebooks/00_Start_here.ipynb`, run its setup cell and first SQL query, then follow notebooks 00–04. Choose the Python workshop kernel if asked. Do not share the Jupyter URL/token.

If the printed localhost URL cannot be reached, first verify setup is still running. Try a different port from the workshop folder:

```bash
bash setup.sh --port 8889
```

Use the newly printed URL. If forwarding still fails, consult [Microsoft's WSL networking guide](https://learn.microsoft.com/windows/wsl/networking) or your IT team; do not expose Jupyter publicly or disable its authentication.

To find the extracted workshop in Windows File Explorer, run `explorer.exe .` in its Ubuntu directory. Save notebook changes through Jupyter with Ctrl+S.

## 5. Optional Ollama model

The core workshop and both CTFs work without an LLM. For the optional AI exercise, the simplest supported path is to run **both Ollama and the Jupyter kernel inside Ubuntu/WSL**, so `localhost:11434` refers to the same environment.

In a second Ubuntu terminal:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama list
```

If `ollama list` cannot connect, start the server and leave that terminal open:

```bash
ollama serve
```

In another Ubuntu terminal, download the model:

```bash
ollama pull qwen3:8b
ollama list
```

Then follow notebook 04's opt-in instructions. Installing Ollama only on the Windows host may require additional WSL networking configuration; the notebook defaults to a local Linux endpoint. Recommend at least 16 GB total system RAM for this extension; Windows and WSL share resources. GPU support depends on compatible hardware and drivers, and CPU runs can be slow. Leave the model exercises disabled if resources are insufficient.

## 6. Open the standalone CTFs

Download the two CTF ZIPs, then extract them from Ubuntu:

```bash
mkdir -p ~/workshops/ctf
unzip "/mnt/c/Users/YOUR_WINDOWS_USER/Downloads/ctf-easy.zip" -d ~/workshops/ctf
unzip "/mnt/c/Users/YOUR_WINDOWS_USER/Downloads/ctf-hard.zip" -d ~/workshops/ctf
```

From your workshop directory, launch Jupyter with the installed environment:

```bash
.workshop-venv/bin/python -m jupyterlab --notebook-dir="$HOME/workshops/ctf"
```

Open `easy/Start.ipynb` or `hard/Start.ipynb` and read its README. If the terminal chooses another port because the workshop's server is still running, use the URL it prints. CTF submission may require event-specific network access; solving the bundled challenges is local.

## Common Windows issues

| Symptom | What to check |
|---|---|
| `sudo`, `bash` or `apt-get` is not recognized | Use the Ubuntu terminal rather than PowerShell |
| `unzip` cannot find the download | Replace the Windows username placeholder; verify your actual Downloads location |
| `ensurepip` or venv creation fails | Install `python3-venv` inside Ubuntu and rerun setup |
| Browser does not open | Paste the full printed localhost URL into the Windows browser |
| `./setup.sh` reports permission denied | Use `bash setup.sh` |
| Notebook data preparation is slow | Keep the extracted workshop under `~/workshops`, rather than `/mnt/c` or OneDrive |
| `ollama` is not found inside Ubuntu | Install Ollama in Ubuntu for the documented local setup |

Automated package validation runs on Linux. The PowerShell launcher and an actual Windows/WSL session still need acceptance testing on a Windows machine before the event.
