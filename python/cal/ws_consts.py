'''
@summary: Sets all the required constants from Wireshark.
'''

########################### FIELD TYPES ############################
(FT_NONE,
 FT_PROTOCOL,
 FT_BOOLEAN,
 FT_UINT8,
 FT_UINT16,
 FT_UINT24,
 FT_UINT32,
 FT_UINT64,
 FT_INT8,
 FT_INT16,
 FT_INT24,
 FT_INT32,
 FT_INT64,
 FT_FLOAT,
 FT_DOUBLE,
 FT_ABSOLUTE_TIME,
 FT_RELATIVE_TIME,
 FT_STRING,
 FT_STRINGZ,
 FT_UINT_STRING,
 FT_ETHER,
 FT_BYTES,
 FT_UINT_BYTES,
 FT_IPv4,
 FT_IPv6,
 FT_IPXNET,
 FT_FRAMENUM,
 FT_PCRE,
 FT_GUID,
 FT_OID,
 FT_EUI64,
 FT_NUM_TYPES) = range(32)
 
######################## DISPLAY VALUES #############################
(BASE_NONE,
 BASE_DEC,
 BASE_HEX,
 BASE_OCT,
 BASE_DEC_HEX,
 BASE_HEX_DEC,
 BASE_CUSTOM) = range(7)
  
######################## DISPLAY VALUES (TIME) #######################
(ABSOLUTE_TIME_LOCAL,
 ABSOLUTE_TIME_UTC,
 ABSOLUTE_TIME_DOY_UTC) = range(1000, 1003)
 
###################### COLUMN IDS ###############################
(COL_8021Q_VLAN_ID,  
 COL_ABS_DATE_TIME,  
 COL_ABS_TIME,       
 COL_CIRCUIT_ID,     
 COL_DSTIDX,         
 COL_SRCIDX,         
 COL_VSAN,           
 COL_CUMULATIVE_BYTES,
 COL_CUSTOM,         
 COL_DCE_CALL,       
 COL_DCE_CTX,        
 COL_DELTA_TIME,     
 COL_DELTA_CONV_TIME,
 COL_DELTA_TIME_DIS, 
 COL_RES_DST,        
 COL_UNRES_DST,      
 COL_RES_DST_PORT,   
 COL_UNRES_DST_PORT, 
 COL_DEF_DST,        
 COL_DEF_DST_PORT,   
 COL_EXPERT,         
 COL_IF_DIR,         
 COL_OXID,           
 COL_RXID,           
 COL_FR_DLCI,        
 COL_FREQ_CHAN,      
 COL_BSSGP_TLLI,     
 COL_HPUX_DEVID,     
 COL_HPUX_SUBSYS,    
 COL_DEF_DL_DST,     
 COL_DEF_DL_SRC,     
 COL_RES_DL_DST,     
 COL_UNRES_DL_DST,   
 COL_RES_DL_SRC,     
 COL_UNRES_DL_SRC,   
 COL_RSSI,           
 COL_TX_RATE,        
 COL_DSCP_VALUE,     
 COL_INFO,           
 COL_COS_VALUE,      
 COL_RES_NET_DST,    
 COL_UNRES_NET_DST,  
 COL_RES_NET_SRC,    
 COL_UNRES_NET_SRC,  
 COL_DEF_NET_DST,    
 COL_DEF_NET_SRC,    
 COL_NUMBER,         
 COL_PACKET_LENGTH,  
 COL_PROTOCOL,       
 COL_REL_TIME,       
 COL_REL_CONV_TIME,  
 COL_DEF_SRC,        
 COL_DEF_SRC_PORT,   
 COL_RES_SRC,        
 COL_UNRES_SRC,      
 COL_RES_SRC_PORT,   
 COL_UNRES_SRC_PORT, 
 COL_TEI,            
 COL_UTC_DATE_TIME,  
 COL_UTC_TIME,       
 COL_CLS_TIME,       
 NUM_COL_FMTS) = range(62)

 
 
################### ENCODINGS #####################
ENC_BIG_ENDIAN = 0x00000000
ENC_LITTLE_ENDIAN = 0x80000000
ENC_TIME_TIMESPEC = 0x00000000
ENC_TIME_NTP = 0x00000002
ENC_CHARENCODING_MASK = 0x7FFFFFFE
ENC_ASCII = 0x00000000
ENC_UTF_8 = 0x00000002
ENC_UTF_16 = 0x00000004
ENC_UCS_2 = 0x00000006
ENC_EBCDIC = 0x00000008
ENC_NA = 0x00000000

################## MISC ###################
HFILL = (0,0,0,0,None,None)

DATA = "data"