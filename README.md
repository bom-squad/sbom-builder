# sbom-builder

This repository contains a command line interface (cli), based on the [protobom](https://github.com/bom-squad/protobom) library, that generates an SBOM from a directory of Windows files. 

## Usage

### Commands
`sbom-builder [flags] file/directory`

### Input
The command accepts a file name or directory name and emits a json SBOM in CycloneDX 1.4 format.  The output file format can be any format supported by [protobom](https://github.com/bom-squad/protobom). The input files are expected to be Windows PE binaries and any supporting files required by those PE binaries.  

### Flags
- `-a`: (string, optional) The analyst name to use as a Person creating the SBOM.  Default:  "analyst name"
- `-f`: (string, optional) The output format (cyclonedx or spdx).  Default:  "cyclonedx"
- `-n`: (string, optional) The software name to use as the SBOM package name.  Default:  "software name"
- `-o`:  (string, optional) Path to write the converted SBOM. Default: stdout.
- `-v`: (string, optional) The software version to use as the SBOM package version.  Default:  "v1.0"
- `-w`: (int, optional) The max number of concurrent workers to use processing files.  Default: 10

### Example 
`% ./sbom-builder -n "PuTTY" -v "0.78" /tmp/PuTTY`

Generate a CycloneDX 1.4 SBOM to stdout for all the files in the directory /tmp/PuTTY.  The top level component for the SBOM should have the name PuTTY with version being 0.78.  ("bom-ref": "PuTTY@0.78")

```
% ./sbom-builder -n PuTTY -v 0.78 /tmp/PuTTY
Adding External node for [GDI32.dll] (Import)..
Adding External node for [IMM32.dll] (Import)..
Adding External node for [ole32.dll] (Import)..
Adding External node for [USER32.dll] (Import)..
Adding External node for [KERNEL32.dll] (Import)..
Adding External node for [SHELL32.dll] (Import)..
Adding External node for [COMDLG32.dll] (Import)..
Adding External node for [ADVAPI32.dll] (Import)..
{
  "$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 0,
  "metadata": {
    "tools": [
      {
        "vendor": "Veramine, Inc",
        "name": "Veramine SBOM",
        "version": "0.2.0"
      }
    ],
    "authors": [
      {
        "name": "analyst name"
      }
    ],
    "component": {
      "bom-ref": "PuTTY@0.78",
      "type": "application",
      "name": "PuTTY"
    }
  },
  "components": [
    {
      "bom-ref": "plink.exe@Release-0.78",
      "type": "application",
      "supplier": {
        "name": "Simon Tatham"
      },
      "name": "plink.exe",
      "version": "Release 0.78",
      "description": "Command-line SSH, Telnet, and Rlogin client",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "4d818fac898da5451ecde24573f895eb9cb08c3773fc4f16cea01db2a2d123aa"
        },
        {
          "alg": "MD5",
          "content": "9405a87f0380218632e5a905144912c9"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
      ],
      "copyright": "Copyright © 1997-2022 Simon Tatham."
    },
    {
      "bom-ref": "GDI32.dll",
      "type": "file",
      "name": "GDI32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "ole32.dll",
      "type": "file",
      "name": "ole32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "SHELL32.dll",
      "type": "file",
      "name": "SHELL32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "putty.exe@Release-0.78-without-embedded-help",
      "type": "application",
      "supplier": {
        "name": "Simon Tatham"
      },
      "name": "putty.exe",
      "version": "Release 0.78 (without embedded help)",
      "description": "SSH, Telnet, Rlogin, and SUPDUP client",
      "hashes": [
        {
          "alg": "SHA-256",
          "content": "35c9df3a348ae805902a95ab8ad32a6d61ef85ca8249ae78f1077edd2429fe6b"
        },
        {
          "alg": "MD5",
          "content": "14080a3e4e877be235f06509b2a4b6a9"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        }
      ],
      "copyright": "Copyright © 1997-2022 Simon Tatham."
    },
    {
      "bom-ref": "IMM32.dll",
      "type": "file",
      "name": "IMM32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "USER32.dll",
      "type": "file",
      "name": "USER32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "pageant.exe@Release-0.78-without-embedded-help",
      "type": "application",
      "supplier": {
        "name": "Simon Tatham"
      },
      "name": "pageant.exe",
      "version": "Release 0.78 (without embedded help)",
      "description": "PuTTY SSH authentication agent",
      "hashes": [
        {
          "alg": "MD5",
          "content": "d5042b0b48c1e0c71e9a129e47e38b20"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        {
          "alg": "SHA-256",
          "content": "8a6377d555bb7f37364553c2a790ea25da85594361b3fbf126578a551705fc31"
        }
      ],
      "copyright": "Copyright © 1997-2022 Simon Tatham."
    },
    {
      "bom-ref": "puttygen.exe@Release-0.78-without-embedded-help",
      "type": "application",
      "supplier": {
        "name": "Simon Tatham"
      },
      "name": "puttygen.exe",
      "version": "Release 0.78 (without embedded help)",
      "description": "PuTTY SSH key generation utility",
      "hashes": [
        {
          "alg": "MD5",
          "content": "14169eaee45a1c21044543efd081ec18"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        {
          "alg": "SHA-256",
          "content": "1abd47a6395ffc9fdc5f1d04910725c51eda1d6afbd400df050c197b7b3f6928"
        }
      ],
      "copyright": "Copyright © 1997-2022 Simon Tatham."
    },
    {
      "bom-ref": "psftp.exe@Release-0.78",
      "type": "application",
      "supplier": {
        "name": "Simon Tatham"
      },
      "name": "psftp.exe",
      "version": "Release 0.78",
      "description": "Command-line interactive SFTP client",
      "hashes": [
        {
          "alg": "MD5",
          "content": "32b3f329f055f95fd29412e2a8597120"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        {
          "alg": "SHA-256",
          "content": "bf4931804c98c13c2696f4adc565f06eb102291b6bc304cce255a8b346fba0a5"
        }
      ],
      "copyright": "Copyright © 1997-2022 Simon Tatham."
    },
    {
      "bom-ref": "pscp.exe@Release-0.78",
      "type": "application",
      "supplier": {
        "name": "Simon Tatham"
      },
      "name": "pscp.exe",
      "version": "Release 0.78",
      "description": "Command-line SCP/SFTP client",
      "hashes": [
        {
          "alg": "MD5",
          "content": "adc18a47dbece6eb700c69ff85055ec7"
        },
        {
          "alg": "SHA-1",
          "content": "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        },
        {
          "alg": "SHA-256",
          "content": "e513a2e0b640097f537e814c1f33a1053bd27d674049a219cefe155f6390b933"
        }
      ],
      "copyright": "Copyright © 1997-2022 Simon Tatham."
    },
    {
      "bom-ref": "KERNEL32.dll",
      "type": "file",
      "name": "KERNEL32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "COMDLG32.dll",
      "type": "file",
      "name": "COMDLG32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    },
    {
      "bom-ref": "ADVAPI32.dll",
      "type": "file",
      "name": "ADVAPI32.dll",
      "description": "File not present in analyzed package. (Most likely a Microsoft binary.)"
    }
  ],
  "dependencies": [
    {
      "ref": "putty.exe@Release-0.78-without-embedded-help",
      "dependsOn": [
        "GDI32.dll",
        "IMM32.dll",
        "ole32.dll",
        "USER32.dll",
        "KERNEL32.dll",
        "SHELL32.dll",
        "COMDLG32.dll",
        "ADVAPI32.dll"
      ]
    },
    {
      "ref": "pageant.exe@Release-0.78-without-embedded-help",
      "dependsOn": [
        "ADVAPI32.dll",
        "GDI32.dll",
        "SHELL32.dll",
        "USER32.dll",
        "KERNEL32.dll",
        "COMDLG32.dll"
      ]
    },
    {
      "ref": "puttygen.exe@Release-0.78-without-embedded-help",
      "dependsOn": [
        "GDI32.dll",
        "SHELL32.dll",
        "USER32.dll",
        "KERNEL32.dll",
        "ADVAPI32.dll",
        "COMDLG32.dll"
      ]
    },
    {
      "ref": "plink.exe@Release-0.78",
      "dependsOn": [
        "KERNEL32.dll",
        "USER32.dll",
        "ADVAPI32.dll"
      ]
    },
    {
      "ref": "psftp.exe@Release-0.78",
      "dependsOn": [
        "KERNEL32.dll",
        "ADVAPI32.dll",
        "USER32.dll"
      ]
    },
    {
      "ref": "pscp.exe@Release-0.78",
      "dependsOn": [
        "KERNEL32.dll",
        "ADVAPI32.dll",
        "USER32.dll"
      ]
    }
  ]
}
```

This tool is currently at "proof-of-concept" phase and will continue to be developed by the [Veramine](https://veramine.com) team.  It is primarily intended at this moment to be a demonstration of the [protobom](https://github.com/bom-squad/protobom) library for SBOM generation and the [saferwall/pe](https://github.com/saferwall/pe) library for Windows file analysis.  

This initial prototype also leverages the [de4dot .NET deobfuscator](https://github.com/ViRb3/de4dot-cex) to attempt to de-obfuscate any .NET binaries that appear to have been obfuscated.  This is an optional requirement.  However, having de4dot.exe available to be run will result in more accurate SBOM documents.  de4dot.exe can be run under mono in Linux and Mac OS X environments, as demonstrated in the current main.go prototype.
