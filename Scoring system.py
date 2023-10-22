# Iterate over each packet in the PCAP file

abc = 0
count_IT_devices = 0
count_OT_devices = 0
ip_addresses = []
for packet in packets:
  if(abc == 100):
    break
  else:
    abc = abc + 1
    # Extract the desired features
    # Check if the packet contains an IP layer
    if IP in packet:
      ip = packet[IP]
      protocol = ip.proto
      ttl = ip.ttl
      src_ip = ip.src

      if TCP in packet:
        tcp = packet[TCP]
        src_port = tcp.sport
        dst_port = tcp.dport
        transport_protocol = 'TCP'
        payload_data = tcp.payload
        # Check if the packet contains a UDP layer
      elif UDP in packet:
        udp = packet[UDP]
        src_port = udp.sport
        dst_port = udp.dport
        transport_protocol = 'UDP'
        payload_data = udp.payload
      else:
        src_port = 'N/A'
        dst_port = 'N/A'
        transport_protocol = 'N/A'
        payload_data = None

          # Check the protocol of the IP packet
      if protocol == 1:
         protocol_name = "ICMP"
         protocol_info = packet[ICMP].summary()
      elif protocol == 6:
         protocol_name = "TCP"
         protocol_info = packet[TCP].summary()
         flags = packet[TCP].flags
      elif protocol == 17:
          protocol_name = "UDP"
          protocol_info = packet[UDP].summary()
      else:
          protocol_name = "Unknown"
          protocol_info = "N/A"


      it_final_score = 0
      ot_final_score = 0
      a = 0
      b = 0
      it_final_score, ot_final_score = get_score(src_port, protocol_name, payload_data)
      if(payload_data != None):
        payload_str = re.sub(r"[^a-zA-Z0-9\s]", "", str(payload_data))
        payload_str = payload_str.lower()
        payload_tokens = nltk.word_tokenize(payload_str)

        combined_keywords = it_protocols_keywords + it_packet_keywords
        model_payload = Word2Vec(sentences=[payload_tokens], vector_size=100, window=5, min_count=1, sg=1)
        model_combined = Word2Vec(sentences=[combined_keywords], vector_size=100, window=5, min_count=1, sg=1)

        filtered_payload_tokens = [token for token in payload_tokens if token in model_combined.wv]
        num_matches1 = 0

        if filtered_payload_tokens:
          similar_payload_keywords = model_payload.wv.most_similar(positive=filtered_payload_tokens, topn=5)
          similar_combined_keywords = model_combined.wv.most_similar(positive=filtered_payload_tokens, topn=5)
          payload_matches = [keyword for keyword, similarity in similar_payload_keywords]
          combined_matches = [keyword for keyword, similarity in similar_combined_keywords]
          num_matches1 = len(set(payload_matches) & set(combined_matches))
        else:
          num_matches1 = 0  # Set a default value if filtered_payload_tokens is empty


        combined_keywords = ot_protocols_keywords + ot_packet_keywords
        model_payload = Word2Vec(sentences=[payload_tokens], vector_size=100, window=5, min_count=1, sg=1)
        model_combined = Word2Vec(sentences=[combined_keywords], vector_size=100, window=5, min_count=1, sg=1)

        filtered_payload_tokens = [token for token in payload_tokens if token in model_combined.wv]
        num_matches2 = 0

        if filtered_payload_tokens:
          similar_payload_keywords = model_payload.wv.most_similar(positive=filtered_payload_tokens, topn=5)
          similar_combined_keywords = model_combined.wv.most_similar(positive=filtered_payload_tokens, topn=5)
          payload_matches = [keyword for keyword, similarity in similar_payload_keywords]
          combined_matches = [keyword for keyword, similarity in similar_combined_keywords]
          num_matches2 = len(set(payload_matches) & set(combined_matches))
        else:
          num_matches2 = 0  # Set a default value if filtered_payload_tokens is empty


        if(num_matches1 > num_matches2):
          it_final_score += 1
        elif(num_matches1 < num_matches2):
          ot_final_score += 1
        else:
          it_final_score += 0


      # Print the extracted features
      print("Start of Packet Information: ", abc, " ---- ")
      print("Source Port: ",(src_port))
      print("Protocol Name: ",(protocol_name))
      print("Payload data: ",(payload_data))
      print(src_ip)

      if(it_final_score > ot_final_score):
        print("On Analysis of above feature, the device is expected to be : IT Network Device")
        print("The confidence score of the scoring system is expected to be : ", (it_final_score*100)/3, "%")
        count_IT_devices += 1
      elif(it_final_score < ot_final_score):
        print("On Analysis of above feature, the device is expected to be : OT Network Device")
        print("The confidence score of the scoring system is expected to be : ", (ot_final_score*100)/3, "%")
        count_OT_devices += 1
      else:
        print("On Analysis of above feature, the device cant be predicted")


      print(it_final_score)
      print(ot_final_score)
      print("End of Packet Information: " , (abc), " ----" )
      print("")


print("Total IT = ",count_IT_devices)
print("Total OT = ", count_OT_devices)
