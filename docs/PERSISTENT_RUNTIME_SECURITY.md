Security properties:

- No production secrets are copied into image build contexts.
- The root `.dockerignore` excludes `.env`, runtime reports, screenshots, PoCs and local configuration.
- Nuclei defaults exclude DoS, intrusive, brute-force and high-noise fuzz templates.
- Update scripts do not remove volumes and do not restart unrelated services.
