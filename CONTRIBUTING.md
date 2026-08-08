# Contributing to TrustGuard

First off, thank you for considering contributing to TrustGuard! It's people like you that make TrustGuard an incredible, 2030-ready internet trust platform.

## Code of Conduct

By participating in this project, you are expected to uphold a welcoming and respectful environment. Please be kind, collaborative, and constructive in all issues and pull requests.

## How Can I Contribute?

### 1. Grab a "Good First Issue"
We have specifically curated issues tagged as `good first issue` in our issue tracker. These are perfect for new contributors to get familiar with the codebase. Before you start working, please comment on the issue so we can assign it to you and avoid duplicate work!

### 2. Set Up Your Local Development Environment

TrustGuard is broken into a FastAPI backend and a React frontend.

**Backend Setup:**
1. Clone the repository: `git clone https://github.com/iamameerhamza/TrustGuard.git`
2. Navigate to the project root: `cd TrustGuard`
3. Create a virtual environment: `python -m venv venv`
4. Activate the virtual environment: 
   - Linux/macOS: `source venv/bin/activate`
   - Windows: `venv\Scripts\activate`
5. Install dependencies: `pip install -r requirements.txt`
6. Run the FastAPI server: `uvicorn app.main:app --reload`

**Running Tests:**
To ensure your changes don't break existing functionality, run our pytest suite:
```bash
pytest tests/
```
All tests must pass (we currently boast a perfect passing suite without making live network calls!).

### 3. Submitting a Pull Request (PR)

1. **Fork** the repository and create a new branch from `main` (e.g., `git checkout -b feature/my-awesome-feature`).
2. Make your changes, ensuring code is clean and adequately commented.
3. If you add new functionality, please add a corresponding test in the `tests/` directory.
4. **Commit** your changes with a descriptive commit message.
5. **Push** your branch to your fork.
6. Open a **Pull Request** against our `main` branch. Provide a clear description of the problem you solved or the feature you added.

### 4. Code Style & Architecture

- **Backend:** We use standard Python PEP8 formatting. Keep `app/main.py` lean; business logic belongs in `app/core/` and `app/modules/`.
- **Frontend:** Standard React/Vite conventions apply.

## Roadmap & Vision

TrustGuard is actively evolving from a simple URL checker into a federated, multi-modal trust engine. Check out our `docs/` folder (specifically the chapters on our architecture) to understand our overarching 2030 vision.

We look forward to reviewing your contributions!
