def is_match_it(protocol_name):
    try:
        lowercased_text = protocol_name.lower()
    except AttributeError:
        return False

    for keyword in it_protocols_keywords:
        if keyword.lower() in lowercased_text:
            return True
    for keyword in it_packet_keywords:
        if keyword.lower() in lowercased_text:
            return True
    return False

def is_match_ot(protocol_name):
    try:
        lowercased_text = protocol_name.lower()
    except AttributeError:
        return False

    for keyword in ot_protocols_keywords:
        if keyword.lower() in lowercased_text:
            return True
    for keyword in ot_packet_keywords:
        if keyword.lower() in lowercased_text:
            return True
    return False


def lowercase_and_remove_chars(text):
    lowercased_text = text.lower()
    cleaned_text = lowercased_text.replace('/', '')
    return cleaned_text

def get_score(src_port, protocol_name, payload_data):
  temp_it_score = 0
  temp_ot_score = 0

  #checking the port
  for i in range(0,len(it_port_keywords)):
    if(src_port == it_port_keywords[i] ):
      temp_it_score = temp_it_score + 1
      break

  for i in range(0,len(ot_port_keywords)):
    if(src_port == ot_port_keywords[i] ):
      temp_ot_score = temp_ot_score + 1
      break



  # checking the protocol_name
  for i in range(0,len(it_protocols_keywords)):
    if((lowercase_and_remove_chars(protocol_name) == lowercase_and_remove_chars(it_protocols_keywords[i])) or is_match_it(protocol_name)):
      temp_it_score = temp_it_score + 1
      break


  for i in range(0,len(ot_protocols_keywords)):
    if((lowercase_and_remove_chars(protocol_name) == lowercase_and_remove_chars(ot_protocols_keywords[i]))  or is_match_ot(protocol_name)):
      temp_ot_score = temp_ot_score + 1
      break


  payload_str = str(payload_data)

  #checking the protocal_name
  if is_match_it(payload_str):
    temp_it_score = temp_it_score + 1
  elif is_match_ot(payload_str):
    temp_ot_score = temp_ot_score + 1
  else:
    temp_it_score *= 1


  if (is_valid_email(payload_str)):
    temp_it_score = temp_it_score + 1
  if(is_valid_website(payload_str)):
    temp_it_score = temp_it_score + 1

  if(re.search(pattern_ot, payload_str )):
    temp_it_score = temp_ot_score + 1

  return temp_it_score, temp_ot_score
