# Project 2 Digital Forensics
#
# Group Members: Nolan Evans (nte0004@auburn.edu), Thomas Root (ter0013@auburn.edu)
# Group: #31  
# Date: November 3, 2023
#
# NOTE: To enable file recovery, uncomment the command at the bottom of the script.

import sys
import os
import binascii
import struct
import io
import math
import hashlib


headers = {
    'bmp' : b'\x42\x4d',
    'gif' : b'\x47\x49\x46\x38\x39\x61',
    'jpg' : b'\xff\xd8\xff\xe0',
    'docx' : b'\x50\x4b\x03\x04\x14\x00\x06\x00',
    'avi' : b'\x52\x49\x46\x46',
    'png' : b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a',
    'pdf' : b'\x25\x50\x44\x46',
    'mpg' : b'\x00\x00\x01'  
    }


trailers = {
    'mpg' : b'\x00\x00\x01\xb7',
    'pdf' : b'\x0a\x25\x25\x45\x4f\x46', 
    'pdf2' : b'\x0A\x25\x25\x45\x4F\x46\x0A', 
    'pdf3' : b'\x0D\x0A\x25\x25\x45\x4F\x46\x0D\x0A',
    'gif' : b'\x00\x00\x3b',
    'jpg' : b'\xff\xd9',
    'docx' : b'\x50\x4b\x05\x06',
    'avi' : b'\x41\x56\x49\x20\x4c\x49\x53\x54',
    'png' : b'\x49\x45\x4e\x44\xae\x42\x60\x82'
    }


mpg_variants = [
    b'\xb3' #b'\xb1', b'\xb2', b'\xb0',
    #b'\xb4', b'\xb5', b'\xb6',
    #b'\xb8', b'\xba', b'\xbb',
    #b'\xbc', b'\xbd', b'\xbe', b'\xbf'
    ] 

# error is a generic function stop the program and raise an error when called
def error(msg):
    sys.exit(f"\nERROR -- {msg}\n")


# Checkfile ensures that the inputted file is a disk drive and exist
def checkFile(file):
    if not file.lower().endswith('.dd'):
        error('File does not end with correct extension: \".dd\"')
    
    pathExist = os.path.exists(file)
    fileExist = os.path.isfile(file)
    if not (pathExist and fileExist):
        error('File not found.')

# readFile returns a byte object of the disk drive
def readFile(file):
    with open(file, 'rb') as f:
        return f.read()

# search finds all instances of a trailer or header from the signature dictionaries above.
# It also keeps count of how many matches are found for each file type.
# This function is ran twice, once for the headers and once for the trailers.

def search(disk_img, start, end, signature_type):
    
    matches = []
    total_counts = []

    for key, val in signature_type.items():
        
        _start = start
        indices = []
        len_val = len(val)
        count = 0

        if signature_type == headers:
            typ = 'header'
        elif signature_type == trailers:
            typ = 'trailer'
        
        offset = disk_img.find(val, _start)

        while offset != -1:
            offset = disk_img.find(val, _start)
            if offset != -1:
                if key == 'mpg' and typ == 'header':
                    next_byte = disk_img[offset + len_val: offset + len_val + 1]
                    if next_byte in mpg_variants:
                        pass
                    else:
                        _start = offset + len_val
                        continue

                count = count + 1
                indices.append(offset)
                _start = offset + len_val

        while indices:
            offset = indices.pop()
            entry = create_entry(key, val, typ, offset)
            matches.append(entry)

        count_entry = {
            'signature' : key,
            'type' : typ,
            'count' : count
            }

        total_counts.append(count_entry)
     
    sorted_total_counts = sorted(total_counts, key=lambda x: x['count'])
    
    # Show number of times each signature was found, uncomment below to enable.
    
    #for entry in sorted_total_counts:
    #   print(entry)

    return matches, sorted_total_counts


# match takes a list of all the offsets found for every header and a list of all the offsets
#   found for each trailer. The parameters "head" and "tail" are the sorted_total_counts from the search function.
#
# match keeps a list of the start and ending offset of found files, this way if another header or trailer is found
#   within the bounds of a seen file, we know that it is safe to ignore.
#
# Since the parameter "head" is a sorted list, it will search from least number of matches for a header to most number.
def match(disk_img, header_offsets, trailer_offsets, head, tail):
    
    seen = []

    for entry in head:
        count = entry['count']
        sig = entry['signature']
        tail_count = 0

        x = sig_list(header_offsets, sig, count)

        if sig != 'bmp':
            tail_count = next(entry['count'] for entry in tail if entry['signature'] == sig)
        
        if sig == 'pdf':
            tail_count = tail_count + next(entry['count'] for entry in tail if entry['signature'] == 'pdf2')
            tail_count = tail_count + next(entry['count'] for entry in tail if entry['signature'] == 'pdf3')

        if sig != 'bmp':
            y = sig_list(trailer_offsets, sig, tail_count)
        
        if len(seen) > 0:
            x = search_bounds(x, seen)
            y = search_bounds(y, seen)

        # Below is only applicable to this disk image, meaningless for other files. Recovery strategy
        #   influenced by manual investigative straegies from class
        #
        # Also, based on the list containing the number of instances a header or trailer was found for a file type.

        if sig == 'gif' or sig == 'png':
            for i in range(count):
                start_offset = x[i]
                
                end_offset = None

                for temp in y:
                    if temp > start_offset and (end_offset is None or temp < end_offset) and not seperated(start_offset, temp, seen):
                        end_offset = temp

                end_offset = end_correct(end_offset, sig)
                seen.append((start_offset, end_offset, sig))
            
        if sig == 'avi':
            for i in range(count):
                start_offset = x[i]

                trailer_offset = y[i]
                size = int.from_bytes(disk_img[start_offset + 4:trailer_offset], 'little')
                
                end_offset = start_offset + size
                
                seen.append((start_offset, end_offset, sig))
        
        if sig == 'pdf': # Relies on the fact that only two headers
            start_offset = max(x)
            
            greater = []
            lesser = []
            
            while y:
                end_offset = y.pop()
                if end_offset > start_offset:
                    greater.append(end_offset)
                else:
                    lesser.append(end_offset)
            
            end_offset = end_correct(max(greater), sig)
            seen.append((start_offset, end_offset, sig))

            start_offset = min(x)
            end_offset = end_correct(max(lesser), sig)
            seen.append((start_offset, end_offset, sig)) 

        if sig == 'docx':
            for i in range(tail_count):
                end_offset = y[i]
                
                start_offset = None

                for temp in x:
                    if temp < end_offset and (start_offset is None or temp < start_offset):
                        start_offset = temp

                end_offset = end_correct(end_offset, sig) + 18
                seen.append((start_offset, end_offset, sig))

        if sig == 'mpg':
            end_offset = y[0]
            x = [val for val in x if on_sector_start(val)]
            start_offset = min(x)

            end_offset = end_correct(end_offset, sig)
            seen.append((start_offset, end_offset, sig))

        if sig == 'bmp':
            x = [val for val in x if on_sector_start(val)]
            promising = []
            for ofst in x:
                size = int.from_bytes(disk_img[ofst + 2: ofst + 6], 'little')
                end_offset = ofst + size

                if not seperated(ofst, end_offset, seen):
                    promising.append((ofst, end_offset, sig))
                    
            seen.append(min(promising))
        
        if sig == 'jpg':
            x = [val for val in x if on_sector_start(val)]
            promising = []

            for ofst in x:
                for ofst_ in y:
                    if (not seperated(ofst, ofst_, seen)) and ofst_ > ofst:
                        promising.append((ofst, ofst_))
            
            bound = min(promising)
            start_offset = bound[0]
            end_offset = end_correct(bound[1], sig)

            seen.append((start_offset, end_offset, sig))

            bound = max(promising) 
            start_offset = bound[0]
            end_offset = end_correct(bound[1], sig)
            
            seen.append((start_offset, end_offset, sig))

    return seen

# Since the search function finds the beginning offset of the trailer, this function corrects for this
#   by adding the length of the trailer to the offset.
def end_correct(ofst, sig):
    val = trailers[sig]
    return ofst + len(val)

# on_sector_start takes advantage of the fact that most header offsets will be at the beginning of a sector.
# It is used to narrow down a pool of possible offsets for a header.
def on_sector_start(ofst):
    tmp = ofst / 512        # 512 is the bytes per sector
    if tmp.is_integer():
        return True
    return False

# seperated test whether or not any two points are seperated by the boundries of a found file.
# If a start offset and end offset are found, we know to ignore it if it is seperated by another file.
def seperated(target, offset, bounds):
    
    bounds_greater = [x for x in bounds if x[0] > target]
    
    for bound in bounds_greater:
        start = bound[0]

        if offset > start:
            return True

    return False

# search_bounds takes a list of header offsets or trailer offsets.
# For each offset it checks that it is not within a previously found file.
# It will return a list of offsets that are not currently in the bounds of a previously found file.
def search_bounds(offsets, bounds):
    safe = []

    for ofst in offsets:
        if not in_bounds(ofst, bounds):
            safe.append(ofst)
    return safe

# in_bounds is used by search_bounds. It test that a point is before or after the bounds of a previously
#   found file. 
def in_bounds(x, bounds):
    for bound in bounds:
        lower = bound[0]
        upper = bound[1]

        if x > lower and x < upper:
            return True
        else:
            return False

# sig_list returns a list of all the offsets of a specific signature name.
# It is used by the match function create a list of offsets to work with for file type
def sig_list(offset_list, sig, count):
    x = []
    _count = 0
    for entry in offset_list:
        if _count >= count:
            break
        if entry['signature'] == sig:
            x.append(entry['offset'])
            _count = _count + 1
        if sig == 'pdf':                # This is an edge case, since pdf may have different trailer, each pdf type is added.
            if entry['signature'] == 'pdf2' or entry['signature'] == 'pdf3':
                x.append(entry['offset'])
                _count = _count + 1

    return x

# create_entry is called by the search function when it finds a signature.
# It returns a dictionary entry to search for easy organization of data.
def create_entry(key, sig, typ, offset):
    file = {
        'signature' : key,
        'signature_bytes' : sig,
        'type': typ,
        'offset' : offset
        }

    return file

# find_data_region uses the FAT16 speec to identify the offset where the data region begins.
# This is useful in narrowing the search for signatures.
# This webiste was helpful: http://www.maverick-os.dk/FileSystemFormats/FAT16_FileSystem.html
def find_data_region(disk_img):
    bytes_per_sector = int.from_bytes(disk_img[11:13], 'little')
    sectors_per_cluster = int.from_bytes(disk_img[13:14], 'little')
    reserved_sectors = int.from_bytes(disk_img[14:16], 'little') 
    root_entries = int.from_bytes(disk_img[17:19], 'little') 
    sectors_per_fat = int.from_bytes(disk_img[22:24], 'little') 
    num_fats = int.from_bytes(disk_img[16:17], 'little')
    
    root_dir = reserved_sectors + (num_fats * sectors_per_fat)
    data_region = root_dir + int((root_entries * 32) / bytes_per_sector)
    
    data_region_offset = data_region * bytes_per_sector
    
    return data_region_offset


# This the main function, it has the following steps:
#   1. Retreive the inputted disk image.
#   1a. Make sure the input is actually an existing disk image. (checkFile)
#   2. Read the disk image. (readFile)
#   3. Search the disk image for header offsets. (search)
#   4. Search the disk image for trailer offsets. (search)
#   5. Match header offsets to the correct trailer offsets. (match)
#   6. Sort the files from lowest starting offset to the highest.
#   7. Generate output for found files, including calculating hash of file.
#   8. Recover files, using output generated.
if __name__ == "__main__":

    if len(sys.argv) < 2:
        error('No input file argument. Correct usage: python3 file-recovery.py <file name>.dd')
    
    file = sys.argv[1]
    checkFile(file)
    
    disk_image = readFile(file) # A byte object of the file
    
    start = find_data_region(disk_image)
    end = len(disk_image) - 1

    header_offsets, head = search(disk_image, start, end, headers)
    trailer_offsets, tail = search(disk_image, start, end, trailers)
    
    files = match(disk_image, header_offsets, trailer_offsets, head, tail)
    
    files = sorted(files, key=lambda x: x[0]) #Sort from low offset to high
    
    for i in range(len(files)):
        name = 'file' + str(i) + '.' + files[i][2]
        start = files[i][0]
        end = files[i][1]
        size = end - start
        
        sha256 = hashlib.sha256(disk_image[start:end]).hexdigest()
        
        print(f"{name}, Start Offset: {start}, End Offset: {end}, SHA-256: {sha256}")
        
        # Recover File
        cmd = f"dd if={file} of={name} bs=1 skip={start} count={size}"
        
        # Un-comment below to recover files
        #os.system(cmd)
