import os
import re
from scapy.all import TCP, rdpcap
import zlib # zlib is commonly used for compression and decompression 
import cv2 # OpenCV (Open Source Computer Vision Library), which is a popular open-source computer vision and machine learning software library


"""
## PREREQUISITES
[*] You just need a .pcap with some images exchanged via HTTP
    [=>] To obtain you own .pcap to try the code do the following:
        - open wirehark on loopback interface
        - open a listener with " nc -lvnp 80"
        - download an image with faces in it 
        - send the image to yourself through HTTP 
            "curl -X POST -H "Content-Type: image/jpeg" --data-binary "@img.jpg" http://127.0.0.1:80 
        - stop wireshark and save the pcap: "file->save as->.pcap"
"""

PIC_DIR = "src/04_SCAPY/01_PCAPics"
PCAP_PATH = "src/04_SCAPY/01_capture.pcap"

def http_assembler():
    """
    Assembles HTTP content from a PCAP file and extracts images.

    Reads in a PCAP file and reconstructs TCP streams. Checks for HTTP requests
    and extracts images from responses if found. Stores images and attempts 
    face detection.

    Returns:
    carved_images (int): Number of images extracted from PCAP.
    faces_detected (int): Number of faces detected in extracted images.
    """

    carved_images = 0
    faces_detected = 0

    # Read the packets
    pkts = rdpcap(PCAP_PATH)

    # Separate TCP sessions and reassemble HTTP packets
    sessions = pkts.sessions() # separate each TCP session into a dictionary.
    for session in sessions:
        http_payload = b""
        for packet in sessions[session]:
            try:
                # filter HTTP traffic
                if packet[TCP].dport == 80 or packet[TCP].sport == 80:
                    # Reassemble the stream
                    # This is effectively the same as right-clicking in Wireshark and selecting Follow TCP Stream.
                    http_payload += bytes(packet[TCP].payload)
            except:
                pass

        # HTTP header parsing function, which will allow us to inspect the HTTP headers individually.
        headers = get_http_headers(http_payload)
        if headers is None:
            continue

    
        # we extract the raw image and return the image type and the binary body of the image itself
        #   and return the image type (MIME) and the binary body of the image itself.
        image, image_type = extract_image(headers, http_payload)
        
        # Validate that we are receiving an image back in an HTTP response
        if image is not None and image_type is not None:
            
            # Store the image
            file_name = f"pic_carver_{carved_images}.{image_type}"
            os.makedirs(PIC_DIR, exist_ok=True) # create dur if not existing
            with open(os.path.join(PIC_DIR, file_name), "wb") as fd:
                fd.write(image)

            carved_images += 1

            # Attempt face detection
            try:
                result = face_detect(f"{PIC_DIR}/{file_name}", file_name, faces_detected)
                if result is True:
                    faces_detected += 1
            except:
                pass

    return carved_images, faces_detected
    
def extract_image(headers, http_payload):
    """Extracts image data from HTTP headers and payload.

    Checks for image content type in headers. Finds start of image 
    data based on header-body separator. Decompresses image if compressed.

    Args:
    headers (dict): HTTP headers
    http_payload (bytes): HTTP payload

    Returns:
    tuple:
    image (bytes): Extracted image bytes 
    image_type (str): Image MIME type
    """

    # Initialize variables to None
    image = None
    image_type = None
    
    if(not headers):
        return None, None
    
    try:
        # Check if "image" is in the "Content-Type" header
        if "image" in headers['Content-Type']:

            # Extract the image type (MIME type) from the "Content-Type" header
            image_type = headers['Content-Type'].split("/")[1]
            
            # Find the beginning of the image data in the HTTP payload
            # - Headers are separated from the body by a blank line -> "\r\n\r\n".
            # - The index method finds the first occurrence of the blank line.
            # - This position marks the end of the HTTP headers and the start of the body.
            # - The blank line "\r\n\r\n" is four characters long, so the +4 brings us to the start of the body.
            image_start = http_payload.index(b"\r\n\r\n") + 4

            
            # Extract the image data
            image = http_payload[image_start:]
            
            # Decompress image if it's compressed (e.g., gzip or deflate)
            try:
                # The "Content-Encoding" header is used to specify the encoding or compression applied to the response body.
                if "Content-Encoding" in headers.keys():
                    if headers['Content-Encoding'] == "gzip":
                        # Decompress "gzip" using zlib with appropriate flags
                        #
                        #    - The "16" flag specifies zlib to automatically detect the header format (zlib or gzip).
                        #    - "lib.MAX_WBITS" is the default window size for zlib and gzip algos.
                        #    => Combining these flags ensures that zlib can handle both zlib and gzip formats.
                        image = zlib.decompress(image, 16 + zlib.MAX_WBITS)
                    elif headers['Content-Encoding'] == "deflate":
                        # Decompress "deflate" compression method using zlib
                        image = zlib.decompress(image)
            except:
                pass
    except:
        # Return None, None if there are errors in extraction
        return None, None

    # Return the extracted image data and image type
    return image, image_type


def get_http_headers(http_payload):
    """Extracts HTTP headers from a HTTP payload.

    Finds the header-body separator in the payload. Decodes the header portion and converts to a dictionary.

    Args:
    http_payload (bytes): The HTTP payload

    Returns:
    dict: The extracted HTTP headers  
    """

    headers = None
    try:
        if http_payload:
            # Find the position of the separator "\r\n\r\n" in the payload
            separator_position = http_payload.find(b"\r\n\r\n")

            # Check if the separator was found
            if separator_position != -1:
                # Obtain the headers part of the http payload
                headers_raw = http_payload[:separator_position + 4].decode("utf-8", errors="ignore")
                headers = dict(re.findall(r"(?P<name>.*?): (?P<value>.*?)\r\n", headers_raw))
    except:
        pass
    
    return headers  # Return None if headers extraction failed


def face_detect(path, file_name, faces_detected):
    """Performs face detection on an image.

    Uses OpenCV's Haar Cascade classifier to detect faces. 
    Draws rectangles around detected faces. Saves the image with faces highlighted.

    Args:
    path (str): Path to the image file
    file_name (str): Name of the image file
    faces_detected (int): Current number of faces detected
    
    Returns:
    bool: True if faces were detected, False otherwise
    """

    img = cv2.imread(path)

    # Use the default Haar Cascade classifier for face detection
    cascade = cv2.CascadeClassifier(
        f'{cv2.data.haarcascades}haarcascade_frontalface_default.xml'
    )    
        
    rects = cascade.detectMultiScale(img, 1.3, 4, cv2.CASCADE_SCALE_IMAGE, (20, 20))

    if len(rects) == 0:
        return False

    rects[:, 2:] += rects[:, :2]

    # Highlight the faces in the image
    for x1, y1, x2, y2 in rects:
        cv2.rectangle(img, (x1, y1), (x2, y2), (127, 255, 0), 2)

    # Construct the full path for saving the image
    
    # Split the file_name into name and extension
    name, ext = os.path.splitext(file_name)    
    save_path = f"{PIC_DIR}/{name}_face_{str(faces_detected) + ext}"
    
    print(f"[*] saving image at {save_path}")
    cv2.imwrite(save_path, img)
    
    return True


def main():
    """
    Calls the http_assembler function to extract images from a PCAP file.
    """
    # Main execution
    carved_images, faces_detected = http_assembler()
    print("Extracted: %d images" % carved_images)
    print("Detected: %d faces" % faces_detected)
    
if __name__ == "__main__":
    main()
