def str_sockaddr_in6(value):
    sin6_port = value["sin6_port"].integer()
    # Convert port from network byte order to host byte order
    port = ((sin6_port & 0xFF) << 8) | ((sin6_port >> 8) & 0xFF)

    sin6_addr = value["sin6_addr"]
    # Extract IPv6 address bytes from sin6_addr.s6_addr (16 bytes)
    addr_bytes = []
    s6_addr = sin6_addr["__u6_addr8"]
    # Read 16 bytes of the IPv6 address
    for i in range(16):
        addr_bytes.append(s6_addr[i].integer() & 0xFF)

    # Convert to IPv6 string representation
    # Group bytes into 16-bit words in network byte order
    words = []
    for i in range(0, 16, 2):
        word = (addr_bytes[i] << 8) | addr_bytes[i + 1]
        words.append(word)

    # Format as IPv6 address with standard notation
    ipv6_parts = [f"{word:x}" for word in words]
    ipv6_str = ":".join(ipv6_parts)

    # Compress consecutive zeros (basic compression)
    # Find longest sequence of consecutive zero groups
    zero_groups = []
    current_zeros = 0
    start_pos = -1

    for i, part in enumerate(ipv6_parts):
        if part == "0":
            if current_zeros == 0:
                start_pos = i
            current_zeros += 1
        else:
            if current_zeros > 0:
                zero_groups.append((start_pos, current_zeros))
                current_zeros = 0

    # Add final group if it ends with zeros
    if current_zeros > 0:
        zero_groups.append((start_pos, current_zeros))

    # Apply compression for longest zero sequence (if > 1)
    if zero_groups:
        longest = max(zero_groups, key=lambda x: x[1])
        if longest[1] > 1:
            start_idx, count = longest
            before = ipv6_parts[:start_idx]
            after = ipv6_parts[start_idx + count:]

            if start_idx == 0:
                ipv6_str = "::" + ":".join(after)
            elif start_idx + count == 8:
                ipv6_str = ":".join(before) + "::"
            else:
                ipv6_str = ":".join(before) + "::" + ":".join(after)
        else:
            ipv6_str = ":".join(ipv6_parts)

    # Create the display value
    display_value = f"[{ipv6_str}]:{port}"
    return display_value


def qdump__sockaddr_in6(d, value):
    d.putValue(f'{str_sockaddr_in6(value)}')
    return


def str_sockaddr_in(value):
    # Extract structure members
    sin_family = value["sin_family"]
    sin_port = value["sin_port"]
    sin_addr = value["sin_addr"]

    # Convert port from network byte order to host byte order
    port = ((sin_port.integer() & 0xFF) << 8) | ((sin_port.integer() >> 8) & 0xFF)

    # Extract IPv4 address from sin_addr.s_addr (4 bytes in network byte order)
    addr_int = sin_addr["s_addr"].integer()

    # Convert 32-bit integer to dotted decimal notation
    # Network byte order means most significant byte first
    byte1 = (addr_int >> 24) & 0xFF
    byte2 = (addr_int >> 16) & 0xFF
    byte3 = (addr_int >> 8) & 0xFF
    byte4 = addr_int & 0xFF

    ipv4_str = f"{byte4}.{byte3}.{byte2}.{byte1}"

    # Create the display value
    display_value = f"{ipv4_str}:{port}"
    return display_value


def qdump__sockaddr_in(d, value):
    # Set the summary display
    d.putValue(str_sockaddr_in(value))
    d.putNumChild(0)


def qdump__in_addr(d, value):
    # Extract the s_addr field (32-bit integer in network byte order)
    addr_int = value["s_addr"].integer()

    # Convert to dotted decimal notation
    byte1 = (addr_int >> 24) & 0xFF
    byte2 = (addr_int >> 16) & 0xFF
    byte3 = (addr_int >> 8) & 0xFF
    byte4 = addr_int & 0xFF

    ipv4_str = f"{byte1}.{byte2}.{byte3}.{byte4}"

    # Set the summary display
    d.putValue(ipv4_str)
    d.putNumChild(2)

    if d.isExpanded():
        with d.children():
            # Show both formatted and raw values
            d.putStringItem("address", ipv4_str)
            d.putIntItem("s_addr_raw", addr_int)


def qdump__InternetAddress(d, value):
#    field_iceAddress = value['ice::NetworkAddress']
#    d.putValue(str(value))
    field_initialized = value['mInitialized'].integer()
    if field_initialized == 0:
        d.putValue('<Empty>')
    else:
        field_ipv4 = value['mAddr4']
        field_ipv6 = value['mAddr6']
        sin_family = field_ipv4['sin_family'].integer()
        if sin_family == 2:
            addr_str = str_sockaddr_in(field_ipv4)
        else:
            addr_str = str_sockaddr_in6(field_ipv6)

        d.putValue(f'{addr_str}')

    d.putNumChild(0)


def qdump__ice__NetworkAddress(d, value):
    qdump__InternetAddress(d,value)

    
def qdump__resip__GenericIPAddress(d, value):
    field_v4 = value['v4Address']
    field_v6 = value['v6Address']
    sin_family = field_v4['sin_family'].integer()
    if sin_family == 2:
        addr_str = str_sockaddr_in(field_v4)
    else:
        addr_str = str_sockaddr_in6(field_v6)

    d.putValue(f'{addr_str}')
    d.putNumChild(0)


def str_resip__TransportType(value: int):
    if value == 0:
        return 'UNKNOWN_TRANSPORT'
    if value == 1:
        return 'TLS'
    if value == 2:
        return 'TCP'
    if value == 3:
        return 'UDP'
    if value == 4:
        return 'SCTP'
    if value == 5:
        return 'DCCP'
    if value == 6:
        return 'DTLS'
    if value == 7:
        return 'WS'
    if value == 8:
        return 'WSS'
    else:
        return 'Other'


def str_resip__Data_as_short_text(d, value):
    # Extract the buffer pointer and size
    buf_ptr = value["mBuf"]
    buf_size = value["mSize"].integer()
    if buf_ptr.pointer() != 0 and buf_size > 0:
        # Read the buffer content as string
        buffer_content = bytes(d.readRawMemory(buf_ptr.pointer(), min(buf_size, 100)))
        try:
            # Try to decode as UTF-8 string
            text_content = buffer_content.decode('utf-8', errors='replace')
            return text_content
        except:
            # If not valid text, show as hex
            hex_content = buffer_content[:16].hex()  # Show first 16 bytes
            return f"0x{hex_content}... ({buf_size} bytes)"
    else:
        return ("nullptr" if buf_ptr.pointer() == 0 else f"empty ({buf_size} bytes)")


def qdump__resip__Data(d, value):
    # Extract the buffer pointer and size
    buf_ptr = value["mBuf"]
    buf_size = value["mSize"].integer()
    
    # Try to interpret buffer as string
    if buf_ptr.pointer() != 0 and buf_size > 0:
        # Read the buffer content as string
        buffer_content = bytes(d.readRawMemory(buf_ptr.pointer(), min(buf_size, 100)))
    
        try:
            # Try to decode as UTF-8 string
            text_content = buffer_content.decode('utf-8', errors='replace')
            
            # Truncate and add ellipsis if too long
            if len(text_content) > 50:
                display_text = text_content[:47] + "..."
            else:
                display_text = text_content
            display_text = f'{display_text} | {buf_size} bytes'
            # d.putValue(f'"{display_text}" ( {buf_size} bytes )')
            d.putValue(display_text)

        except:
            # If not valid text, show as hex
            hex_content = buffer_content[:16].hex()  # Show first 16 bytes
            d.putValue(f"0x{hex_content}... | {buf_size} bytes")
    else:
        d.putValue("nullptr" if buf_ptr.pointer() == 0 else f"empty | {buf_size} bytes")

    d.putNumChild(0)  # mBuf, mSize, and buffer content

    # if d.isExpanded():
    #     with d.children():
    #         # Show the raw pointer
    #         d.putSubItem("mBuf", buf_ptr)

    #         # Show the size
    #         d.putSubItem("mSize", value["mSize"])

    #         # Show buffer contents in detail
    #         if buf_ptr.pointer() != 0 and buf_size > 0:
    #             # Create a synthetic child for the buffer content
    #             d.putItem("buffer_content", "")
    #             d.putItemCount(min(buf_size, 256))  # Show up to 256 bytes

    #             # You can also show it as different types:

    #             # As string
    #             buffer_data = bytes(d.readRawMemory(buf_ptr.pointer(), buf_size))
    #             try:
    #                 text_data = buffer_data.decode('utf-8', errors='replace')
    #                 d.putStringItem("as_string", text_data)
    #             except:
    #                 d.putStringItem("as_string", "<invalid UTF-8>")

    #             # As hex dump (first 64 bytes)
    #             # hex_data = buffer_data[:64].hex()
    #             # formatted_hex = ' '.join(hex_data[i:i+2] for i in range(0, len(hex_data), 2))
    #             # d.putStringItem("as_hex", formatted_hex)

    #             # As array of bytes
    #             # d.putArrayData(buf_ptr, buf_size, d.lookupType("char"))


def qdump__resip__Tuple(d, value):
    field_flowkey = value['mFlowKey'].integer()
    field_transportkey = value['mTransportKey'].integer()
    field_v4 = value['m_anonv4']
    field_v6 = value['m_anonv6']
    sin_family = field_v4['sin_family'].integer()
    if sin_family == 2:
        addr_str = str_sockaddr_in(field_v4)
    else:
        addr_str = str_sockaddr_in6(field_v6)
    field_transporttype = str_resip__TransportType(value['mTransportType'].integer())

    field_targetdomain = str_resip__Data_as_short_text(d, value['mTargetDomain'])
    display_value = f'{addr_str}, flow key: {field_flowkey}, transport key: {field_transportkey}, type: {field_transporttype}, target: {field_targetdomain}'
    # addr_str = ''
    # display_value = f'{addr_str}, flow key: {field_flowkey}, transport key: {field_transportkey}'
    d.putValue(display_value)
    d.putNumChild(0)


def separate_digits_by_groups(number):
    """
    Separates digits in a number into groups of 3 using dots.
    
    Args:
        number: An integer or string representation of a number
    
    Returns:
        A string with digits grouped by 3 and separated by dots
    """
    # Handle negative numbers
    is_negative = int(number) < 0
    num_str = str(abs(int(number)))
    
    # Split into groups of 3 from right to left
    groups = []
    while len(num_str) > 3:
        groups.append(num_str[-3:])
        num_str = num_str[:-3]
    
    # Add remaining digits as the last group
    if num_str:
        groups.append(num_str)
    
    # Reverse and join groups with dots
    result = '.'.join(reversed(groups))
    
    # Add negative sign back if needed
    if is_negative:
        result = '-' + result
    
    return result

import datetime
def microseconds_to_datetime(microseconds):
    """
    Converts microseconds since Unix epoch to readable date and time string.
    
    Args:
        microseconds: Number of microseconds since Unix epoch (January 1, 1970, 00:00:00 UTC)
    
    Returns:
        A string representation of the date and time
    """
    # Convert microseconds to seconds (Unix timestamp)
    timestamp = microseconds / 1_000_000
    
    # Create datetime object from timestamp
    dt = datetime.datetime.fromtimestamp(timestamp)
    
    # Return formatted string
    return dt.strftime("%Y-%m-%d %H:%M:%S.%f")


def qdump__std__chrono__microseconds(d, value):
    field_r = value['__r'].integer()
    display_value = separate_digits_by_groups(field_r)
    dt_value = microseconds_to_datetime(field_r)

    d.putValue(f'{display_value} | {dt_value}')

def qdump__timeval(d, value):
    field_sec = value['tv_sec'].integer()       # Seconds
    field_msec = value['tv_usec'].integer()     # Microseconds
    dt_value = microseconds_to_datetime(field_sec * 1000000 + field_msec)
    d.putValue(f'{dt_value}')


def qdump__timesec(d, value):
    field_sec = value['tv_sec'].integer()       # Seconds
    field_nsec = value['tv_nsec'].integer()     # Nanoseconds
    dt_value = microseconds_to_datetime(field_sec * 1000000 + int(field_nsec / 1000))
    d.putValue(f'{dt_value}')


def qdump__std__atomic_int(d, value):
    field_i = value['_M_i'].integer()
    d.putValue(f'{field_i}')