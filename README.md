# file2hashcat

Extract hashes from your files into a format suitable for use with hashcat.

## Prerequisites

```
sudo apt-get install python3 perl liblzma-dev zlib
sudo cpan -i Compress::Raw::Zlib
sudo cpan -i Compress::Raw::Lzma
```

## Usage

Extract and print hash:
```
python3 file2hashcat.py your-file
```

Extract and print hash and hash type number:
```
python3 file2hashcat.py your-file -t
```


## Docker version

Build image:
```
docker build -t file2hashcat .
```

Linux:
```
docker run -v $(pwd):/app file2hashcat your-file
```

Windows (cmd):
```
docker run -v %cd%:/app file2hashcat your-file
```
