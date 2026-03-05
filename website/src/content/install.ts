export const installMethods = [
  {
    id: 'brew',
    label: 'Homebrew',
    code: 'brew install AnasSahel/tap/vulnex',
  },
  {
    id: 'go',
    label: 'Go Install',
    code: 'go install github.com/trustin-tech/vulnex@latest',
  },
  {
    id: 'binary',
    label: 'Binary',
    code: `# Download from GitHub Releases
curl -sL \\
  https://github.com/AnasSahel/vulnex/releases/latest/download/vulnex_linux_amd64.tar.gz \\
  | tar xz
sudo mv vulnex /usr/local/bin/`,
  },
  {
    id: 'source',
    label: 'Source',
    code: `git clone https://github.com/AnasSahel/vulnex.git
cd vulnex
make build`,
  },
];
