# Start here: Kubernetes detection workshop

Download **workshop-student.zip** for the guided workshop. Download **ctf-easy.zip** and **ctf-hard.zip** separately for independent practice; the CTFs have their own datasets and do not require the workshop to be running.

## Before the workshop

Use macOS, Linux, or Windows (native PowerShell or WSL2); Python 3.10+ (3.11 recommended); a browser; and about 8 GB RAM. Installation requires internet access for Python packages. No Kubernetes cluster, cloud account, credentials or paid API is required.

1. Extract `workshop-student.zip` into a writable directory. Windows users: use the native PowerShell instructions below, or the WSL alternative.
2. On macOS/Linux, open a terminal inside the extracted `workshop-student/` folder and run:
   ```bash
   ./setup.sh
   ```
   If your extraction tool lost executable permissions, use `bash setup.sh`.
3. Open the token-bearing Jupyter URL printed in that terminal. Keep the terminal open.
4. Open `notebooks/00_Start_here.ipynb`, run setup, and run its first SQL query. Do this before the workshop to catch installation problems.
5. Follow notebooks **00 → 01 → 02 → 03 → 04**, using `WORKSHOP.md`. TODOs are intentionally incomplete. Use the collapsed hints when needed.

The core exercises use bundled synthetic data and run offline after installation. These downloads are not a fully offline Python installer: no virtual environment, package wheels or model weights are bundled.

## Windows or a DEATHCon Windows VM: native PowerShell

No WSL, additional VM or nested virtualization is required. Install **64-bit Python 3.10+ (3.11 recommended)** from python.org, including the Python launcher. Extract the workshop ZIP to a local folder outside OneDrive, open ordinary PowerShell in that folder, then run:

```powershell
py -3 --version
Unblock-File .\setup.ps1
powershell.exe -NoProfile -ExecutionPolicy RemoteSigned -File .\setup.ps1
```

Review the script before unblocking it. This uses a process-only execution policy; it does not change machine-wide policy. If organizational policy blocks it, ask IT or the event organizers for help. No administrator rights are needed for the workshop launcher.

Keep PowerShell open and use its Jupyter URL in your Windows browser. Add `-Port 8889` to choose another port or `-PrepareOnly` to install without opening Jupyter. The environment's executable is `.\.workshop-venv\Scripts\python.exe`; you do not need to activate it. Use that executable to launch the extracted CTF folders with `-m jupyterlab --notebook-dir=C:\path\to\ctf`.

For the optional model, install Ollama for Windows **inside the same Windows system/VM as Jupyter**, start it, then run `ollama pull qwen3:8b`. Skip the model in a small VM. The extracted workshop includes `docs/windows-setup.md` with full native and WSL instructions.

## Alternative: WSL2 on your Windows host

Open **PowerShell as Administrator**:

```powershell
wsl --install -d Ubuntu
```

Restart if prompted. Open **Ubuntu** from the Start menu and create its Linux username/password. All subsequent commands run in Ubuntu, not PowerShell.

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip unzip git curl zstd
python3 --version
mkdir -p ~/workshops
unzip "/mnt/c/Users/YOUR_WINDOWS_USER/Downloads/workshop-student.zip" -d ~/workshops
cd ~/workshops/workshop-student
bash setup.sh
```

Replace `YOUR_WINDOWS_USER` with the Windows profile folder holding your Downloads; adjust the download path if needed. Python must be 3.10+. Keep the extracted workshop inside Ubuntu's home directory, rather than OneDrive or `/mnt/c`.

Paste the complete Jupyter localhost URL printed in Ubuntu into your normal Windows browser. Keep Ubuntu's setup terminal open. The extracted workshop includes `docs/windows-setup.md` with detailed WSL2, browser, optional Ollama and CTF instructions.

No Windows VM, domain join, Sysmon or Sentinel is needed for this workshop. Tailscale is only needed if the event uses private download/submission endpoints. Install and run optional Ollama inside Ubuntu alongside the Jupyter kernel for the documented localhost connection.

## Optional local AI investigator

Complete the core workshop without an LLM first. Notebook 04 includes Ollama installation and model-download steps, plus a raw-versus-normalized comparison you can run yourself. Allow extra time beyond the core hour.

Recommend 16 GB RAM or more and several GB of storage for `qwen3:8b`. A GPU helps; CPU runs may be slow. Ollama must run on the same machine as the Jupyter kernel. On Debian/Ubuntu, install the extraction prerequisite before installing Ollama:

```bash
sudo apt-get update
sudo apt-get install -y zstd
```

Follow notebook 04 for the remaining steps. No model is started automatically.

## CTF practice

For a 60-minute extension after notebooks 01–04, open
`notebooks/05_Detect_service_account_deviations.ipynb` in the workshop JupyterLab session. Follow its steps
to map three clouds' control-plane logs and detect service accounts doing something
new. The extension is included in the student workshop ZIP.

Extract each CTF ZIP into its own directory, read its `README.md`, and open `Start.ipynb`. The workshop's Python environment can open them without reinstalling dependencies. After the workshop setup has installed Jupyter, launch it from the workshop folder in a new terminal with:

```bash
.workshop-venv/bin/python -m jupyterlab --notebook-dir=/path/to/extracted/ctf/folders
```

Use the directory containing the extracted `easy/` and `hard/` folders. Select the workshop Python kernel. Each challenge notebook opens its own database read-only. HINTS.md contains progressive hints. Submit flags through the event's CTF platform; answer keys are not part of the student downloads.

## Verify downloads

On Linux or Ubuntu/WSL: `sha256sum -c SHA256SUMS`. On macOS: `shasum -a 256 -c SHA256SUMS`. Download all three ZIPs and START-HERE.md first, or verify only the files you downloaded individually. These checks detect incomplete or changed downloads; they do not authenticate a file server you do not trust.

## Common setup issues

- Python missing or too old: install Python 3.10+; on Linux you may need your distribution's Python venv package.
- Package download fails: check internet access or your organization's approved package mirror.
- Notebook reports setup is missing: run its first Python setup cell. After editing a mapping, rerun that mapping cell before normalization.
- An exercise reports a TODO is incomplete: fill it using the hints; this is expected in the student edition.
- Ollama connection fails: check `ollama list`, start the server/application, and confirm the selected model was downloaded on the Jupyter machine.

Use the event's published help channel for unresolved setup issues; do not share Jupyter access tokens or credentials.
