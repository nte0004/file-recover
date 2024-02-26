## File Recovery Based On File Headers/Trailers
This script will search through a supplied disk image and recover certain files.

This project was part of a Digital Forensics course I took at Auburn. It's use cases are fairly limited and it isn't perfect.

The following file types will be searched for:
- bmp
- gif
- jpg
- docx
- avi
- png
- pdf
- mpg

### Use

When running the project, supply a disk image.
`python3 file-recovery.py <disk image>`

Make sure to uncomment the last line in the script to actually recover the files, otherwise it'll only list files found.
