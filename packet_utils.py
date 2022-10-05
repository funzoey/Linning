from pathlib import Path
from scapy.layers.dns import DNS
from scapy.layers.inet import TCP
from scapy.packet import Padding
from scapy.utils import rdpcap

"""
# for traffic identification
PREFIX_TO_TRAFFIC_ID_NONVPN = {
    # Chat
    'aim_chat_3a': 0,
    'aim_chat_3b': 0,
    'aimchat1': 0,
    'aimchat2': 0,
    'facebook_chat_4a': 0,
    'facebook_chat_4b': 0,
    'facebookchat1': 0,
    'facebookchat2': 0,
    'facebookchat3': 0,
    'hangout_chat_4b': 0,
    'hangouts_chat_4a': 0,
    'icq_chat_3a': 0,
    'icq_chat_3b': 0,
    'icqchat1': 0,
    'icqchat2': 0,
    'skype_chat1a': 0,
    'skype_chat1b': 0,
    # Email
    'email1a': 1,
    'email1b': 1,
    'email2a': 1,
    'email2b': 1,
    'gmailchat1': 1,
    'gmailchat2': 1,
    'gmailchat3': 1,
    # File Transfer
    'ftps_down_1a': 2,
    'ftps_down_1b': 2,
    'ftps_up_2a': 2,
    'ftps_up_2b': 2,
    'scp1': 2,
    'scpdown1': 2,
    'scpdown2': 2,
    'scpdown3': 2,
    'scpdown4': 2,
    'scpdown5': 2,
    'scpdown6': 2,
    'scpup1': 2,
    'scpup2': 2,
    'scpup3': 2,
    'scpup5': 2,
    'scpup6': 2,
    'sftp1': 2,
    'sftp_down_3a': 2,
    'sftp_down_3b': 2,
    'sftp_up_2a': 2,
    'sftp_up_2b': 2,
    'sftpdown1': 2,
    'sftpdown2': 2,
    'sftpup1': 2,
    'skype_file1': 2,
    'skype_file2': 2,
    'skype_file3': 2,
    'skype_file4': 2,
    'skype_file5': 2,
    'skype_file6': 2,
    'skype_file7': 2,
    'skype_file8': 2,
    # Streaming
    'facebook_video1a': 3,
    'facebook_video1b': 3,
    'facebook_video2a': 3,
    'facebook_video2b': 3,
    'hangouts_video1b': 3,
    'hangouts_video2a': 3,
    'hangouts_video2b': 3,
    'netflix1': 3,
    'netflix2': 3,
    'netflix3': 3,
    'netflix4': 3,
    'skype_video1a': 3,
    'skype_video1b': 3,
    'skype_video2a': 3,
    'skype_video2b': 3,
    'vimeo1': 3,
    'vimeo2': 3,
    'vimeo3': 3,
    'vimeo4': 3,
    'youtube1': 3,
    'youtube2': 3,
    'youtube3': 3,
    'youtube4': 3,
    'youtube5': 3,
    'youtube6': 3,
    'youtubehtml5_1': 3,
    # VoIP
    'facebook_audio1a': 4,
    'facebook_audio1b': 4,
    'facebook_audio2a': 4,
    'facebook_audio2b': 4,
    'facebook_audio3': 4,
    'facebook_audio4': 4,
    'hangouts_audio1a': 4,
    'hangouts_audio1b': 4,
    'hangouts_audio2a': 4,
    'hangouts_audio2b': 4,
    'hangouts_audio3': 4,
    'hangouts_audio4': 4,
    'skype_audio1a': 4,
    'skype_audio1b': 4,
    'skype_audio2a': 4,
    'skype_audio2b': 4,
    'skype_audio3': 4,
    'skype_audio4': 4,
    'voipbuster_4a': 4,
    'voipbuster_4b': 4,
    'voipbuster1b': 4,
    'voipbuster2b': 4,
    'voipbuster3b': 4,
}
"""

"""
#endtoend
PREFIX_TO_TRAFFIC_ID_NONVPN = {
    # Chat
    'aim_chat_3a': 0,
    'aim_chat_3b': 0,
    'aimchat1': 0,
    'aimchat2': 0,
    'facebook_chat_4a': 0,
    'facebook_chat_4b': 0,
    'facebookchat1': 0,
    'facebookchat2': 0,
    'facebookchat3': 0,
    'hangout_chat_4b': 0,
    'hangouts_chat_4a': 0,
    'icq_chat_3a': 0,
    'icq_chat_3b': 0,
    'icqchat1': 0,
    'icqchat2': 0,
    'skype_chat1a': 0,
    'skype_chat1b': 0,
    # Email
    'email1a': 1,
    'email1b': 1,
    'email2a': 1,
    'email2b': 1,
    'gmailchat1': 1,
    'gmailchat2': 1,
    'gmailchat3': 1,
    # File Transfer
    'skype_file1': 2,
    'skype_file2': 2,
    'skype_file3': 2,
    'skype_file4': 2,
    'skype_file5': 2,
    'skype_file6': 2,
    'skype_file7': 2,
    'skype_file8': 2,
    # Streaming
    'netflix1': 3,
    'netflix2': 3,
    'netflix3': 3,
    'netflix4': 3,
    'spotify1': 3,
    'spotify2': 3,
    'spotify3': 3,
    'spotify4': 3,
    'vimeo1': 3,
    'vimeo2': 3,
    'vimeo3': 3,
    'vimeo4': 3,
    'youtube1': 3,
    'youtube2': 3,
    'youtube3': 3,
    'youtube4': 3,
    'youtube5': 3,
    'youtube6': 3,
    'youtubehtml5_1': 3,
    # VoIP
    'hangouts_audio1a': 4,
    'hangouts_audio1b': 4,
    'hangouts_audio2a': 4,
    'hangouts_audio2b': 4,
    'hangouts_audio3': 4,
    'hangouts_audio4': 4,
    # P2P
    'torrent01':5
}
"""

"""
#自己改的
PREFIX_TO_TRAFFIC_ID_NONVPN = {
    # Chat
    'aim_chat_3a': 0,
    'aim_chat_3b': 0,
    'aimchat1': 0,
    'aimchat2': 0,
    'facebook_chat_4a': 0,
    'facebook_chat_4b': 0,
    'facebookchat1': 0,
    'facebookchat2': 0,
    'facebookchat3': 0,
    'hangout_chat_4b': 0,
    'hangouts_chat_4a': 0,
    'icq_chat_3a': 0,
    'icq_chat_3b': 0,
    'icqchat1': 0,
    'icqchat2': 0,
    'skype_chat1a': 0,
    'skype_chat1b': 0,
    # Email
    'email1a': 1,
    'email1b': 1,
    'email2a': 1,
    'email2b': 1,
    'gmailchat1': 1,
    'gmailchat2': 1,
    'gmailchat3': 1,
    # File Transfer
    'ftps_down_1a': 2,
    'ftps_down_1b': 2,
    'ftps_up_2a': 2,
    'ftps_up_2b': 2,
    # Streaming
    'vimeo1': 3,
    'vimeo2': 3,
    'vimeo3': 3,
    'vimeo4': 3,
    'youtube1': 3,
    'youtube2': 3,
    'youtube3': 3,
    'youtube4': 3,
    'youtube5': 3,
    'youtube6': 3,
    'youtubehtml5_1': 3,
    # VoIP
    'hangouts_audio1a': 4,
    'hangouts_audio1b': 4,
    'hangouts_audio2a': 4,
    'hangouts_audio2b': 4,
    'hangouts_audio3': 4,
    'hangouts_audio4': 4,
    # P2P
    'torrent01':5
}
"""

"""
endtoend
PREFIX_TO_TRAFFIC_ID_VPN ={
    # VPN: Chat
    'vpn_aim_chat1a': 0,
    'vpn_aim_chat1b': 0,
    'vpn_chat': 0,
    'vpn_facebook_chat1a': 0,
    'vpn_facebook_chat1b': 0,
    'vpn_hangouts_chat1a': 0,
    'vpn_hangouts_chat1b': 0,
    'vpn_icq_chat1a': 0,
    'vpn_icq_chat1b': 0,
    'vpn_skype_chat1a': 0,
    'vpn_skype_chat1b': 0,
    # VPN: Email
    'vpn_email2a': 1,
    'vpn_email2b': 1,
    # VPN: File Transfer
    'vpn_ftps_a': 2,
    'vpn_ftps_b': 2,
    'vpn_sftp_a': 2,
    'vpn_sftp_b': 2,
    'vpn_skype_files1a': 2,
    'vpn_skype_files1b': 2,
    # VPN: Streaming
    'vpn_netflix_a': 3,
    'vpn_spotify_a':3,
    'vpn_vimeo_a': 3,
    'vpn_vimeo_b': 3,
    'vpn_youtube_a': 3,
    # VPN VoIP
    'vpn_facebook_audio2': 4,
    'vpn_hangouts_audio1': 4,
    'vpn_hangouts_audio2': 4,
    'vpn_skype_audio1': 4,
    'vpn_skype_audio2': 4,
    'vpn_voipbuster1a': 4,
    'vpn_voipbuster1b': 4,
    # VPN P2P
    'vpn_bittorrent': 5
}
"""

#按照end-to-end的分类nonvpn
PREFIX_TO_TRAFFIC_ID_NONVPN = {
    # Chat
    'aim_chat_3a': 0,
    'aim_chat_3b': 1,
    'aimchat1': 2,
    'aimchat2': 3,
    'facebook_chat_4a': 4,
    'facebook_chat_4b': 5,
    'facebookchat1': 6,
    'facebookchat2': 7,
    'facebookchat3': 8,
    'hangout_chat_4b': 9,
    'hangouts_chat_4a': 10,
    'icq_chat_3a': 11,
    'icq_chat_3b': 12,
    'icqchat1': 13,
    'icqchat2': 14,
    'skype_chat1a': 15,
    'skype_chat1b': 16,
    'aim_chat': 17,
    'aimchat': 18,
    'facebook_chat': 19,
    'facebookchat': 20,
    'hangout_chat': 21,
    'hangoutschat': 22,
    'icq_chat': 23,
    'icqchat': 24,
    'skypechat': 25,
    'skype_chat': 26,
    # File Transfer
    'skype_file1': 27,
    'skype_file2': 28,
    'skype_file3': 29,
    'skype_file4': 30,
    'skype_file5': 31,
    'skype_file6': 32,
    'skype_file7': 33,
    'skype_file8': 34,
    'ftp_filetransfer':35,
    'sftp_filetransfer':36,
    # Streaming
    'netflix1': 37,
    'netflix2': 38,
    'netflix3': 39,
    'netflix4': 40,
    'spotify1': 41,
    'spotify2': 42,
    'spotify3': 43,
    'spotify4': 44,
    'vimeo1': 45,
    'vimeo2': 46,
    'vimeo3': 47,
    'vimeo4': 48,
    'youtube1': 49,
    'youtube2': 50,
    'youtube3': 51,
    'youtube4': 52,
    'youtube5': 53,
    'youtube6': 54,
    'youtubehtml5_1': 55,
    'vimeo_workstation':56,
    'youtube_flash_workstation': 57,
    'youtube_html5_workstation': 58,
    # VoIP
    'hangouts_audio1a': 59,
    'hangouts_audio1b': 60,
    'hangouts_audio2a': 61,
    'hangouts_audio2b': 62,
    'hangouts_audio3': 63,
    'hangouts_audio4': 64,
    'facebook_audio':65,
    'hangout_audio':66,
    'skype_audio':67,
    # BROWSING
    'browsing':68,
    'browsing_ara':69,
    'browsing_ara2':70,
    'browsing_ger':71,
    'browsing2':72,
    'browsing2-1':73,
    'browsing2-2':74,
    'ssl_browsing':75
}

#按照end-to-end的分类vpn
PREFIX_TO_TRAFFIC_ID_VPN ={
    # VPN: Chat
    'vpn_aim_chat1a': 0,
    'vpn_aim_chat1b': 1,
    'vpn_chat': 2,
    'vpn_facebook_chat1a': 3,
    'vpn_facebook_chat1b': 4,
    'vpn_hangouts_chat1a': 5,
    'vpn_hangouts_chat1b': 6,
    'vpn_icq_chat1a': 7,
    'vpn_icq_chat1b': 8,
    'vpn_skype_chat1a': 9,
    'vpn_skype_chat1b': 10,
    # VPN: File Transfer
    'vpn_ftps_a': 11,
    'vpn_ftps_b': 12,
    'vpn_sftp_a': 13,
    'vpn_sftp_b': 14,
    'vpn_skype_files1a': 15,
    'vpn_skype_files1b': 16,
    # VPN: Streaming
    'vpn_netflix_a': 17,
    'vpn_spotify_a':18,
    'vpn_vimeo_a': 19,
    'vpn_vimeo_b': 20,
    'vpn_youtube_a': 21,
    # VPN VoIP
    'vpn_facebook_audio2': 22,
    'vpn_hangouts_audio1': 23,
    'vpn_hangouts_audio2': 24, #没有
    'vpn_skype_audio1': 25,
    'vpn_skype_audio2': 26,
    'vpn_voipbuster1a': 27,
    'vpn_voipbuster1b': 28,
}

PREFIX_TO_TRAFFIC_ID_TOR ={
    # TOR: Chat
    'tor_chat_aimchatgateway': 0,
    'tor_chat_facebookchatgateway': 1,
    'tor_chat_gate_aim_chat': 2,
    'tor_chat_gate_facebook_chat': 3,
    'tor_chat_gate_hangout_chat': 4,
    'tor_chat_gate_icq_chat': 5,
    'tor_chat_gate_skype_chat': 6,
    'tor_chat_hangoutschatgateway': 7,
    'tor_chat_icqchatgateway': 8,
    'tor_chat_skypechatgateway': 9,
    # # TOR: Email
    # 'tor_mail_gateway_thunderbird_imap': 10,
    # 'tor_mail_gateway_thunderbird_pop': 11,
    # 'tor_mail_gate_email_imap_filetransfer': 12,
    # 'tor_mail_gate_pop_filetransfer': 13,
    # TOR: File Transfer
    'tor_file-transfer_gate_ftp_transfer': 10,
    'tor_file-transfer_gate_sftp_filetransfer': 11,
    'tor_file-transfer_tor_skype_transfer': 12,
    # TOR: Streaming
    'tor_video_vimeo_gateway': 13,
    'tor_video_youtube_flash_gateway':14,
    'tor_video_youtube_html5_gateway': 15,
    # TOR VoIP
    'tor_voip_facebook_voice_gateway': 16,
    'tor_voip_gate_facebook_audio': 17,
    'tor_voip_gate_hangout_audio': 18,
    'tor_voip_gate_skype_audio': 19,
    'tor_voip_hangouts_voice_gateway': 20,
    'tor_voip_skype_voice_gateway': 21,
    # # TOR P2P
    # 'tor_p2p_tor_p2p_multiplespeed': 26,
    # 'tor_p2p_tor_p2p_vuze': 27,
    # 'tor_tor_p2p_multiplespeed2-1': 28,
    # 'tor_tor_p2p_vuze-2-1': 29,
    # TOR Browsing
    'tor_browsing_gate_ssl_browsing':22,
    'tor_browsing_ssl_browsing_gateway':23,
    'tor_browsing_tor_browsing_ara':24,
    'tor_browsing_tor_browsing_ger':25,
    'tor_browsing_tor_browsing_mam':26,
    'tor_browsing_tor_browsing_mam2':27
}


#其实只用到了vpn：voip 共12类
ID_TO_TRAFFIC_NONVPN = {
    0: 'Chat',
    1: 'File Transfer',
    2: 'Streaming',
    3: 'Voip',
    4: 'Browsing'
}


ID_TO_TRAFFIC_VPN = {
    0: 'VPN: Chat',
    1: 'VPN: File Transfer',
    2: 'VPN: Streaming',
    3: 'VPN: Voip'
}

ID_TO_TRAFFIC_TOR = {
    0: 'TOR: Chat',
    1: 'TOR: File Transfer',
    2: 'TOR: Streaming',
    3: 'TOR: Voip',
    4: 'TOR: Browsing' 
}


PREFIX_TO_TRAFFIC_ID_APP_VPN = {
    # AIM Chat
    'vpn_aim_chat1a': 0,
    'vpn_aim_chat1b': 1,
    # Email
    'vpn_email2a': 2,
    'vpn_email2b': 3,
    # Facebook
    'vpn_facebook_audio2': 4,
    'vpn_facebook_chat1a': 5,
    'vpn_facebook_chat1b': 6,
    # FTPS 
    'vpn_ftps_a': 7,
    'vpn_ftps_b': 8, 
    # Gmail 
    # Hangouts 
    'vpn_hangouts_audio1': 9,
    'vpn_hangouts_audio2': 10,
    'vpn_hangouts_chat1a': 11,
    'vpn_hangouts_chat1b': 12,
    # ICQ
    'vpn_icq_chat1a': 13,
    'vpn_icq_chat1b': 14, 
    # Netflix 
    'vpn_netflix_a': 15,
    # SCP
    # SFTP
    'vpn_sftp_a': 16,
    'vpn_sftp_b': 17,
    # Skype 
    'vpn_skype_audio1': 18,
    'vpn_skype_audio2': 19,
    'vpn_skype_chat1a': 20,
    'vpn_skype_chat1b': 21,
    'vpn_skype_files1a': 22,
    'vpn_skype_files1b': 23,
    # Spotify 
    'vpn_spotify_a': 24,
    # Torrent 
    'vpn_bittorrent': 25,
    # Tor
    # VoipBuster 
    'vpn_voipbuster1a': 26,
    'vpn_voipbuster1b': 27,
    # Vimeo 
    'vpn_vimeo_a': 28,
    'vpn_vimeo_b': 29,  
    # YouTube
    'vpn_youtube_a': 30,
   
}

PREFIX_TO_TRAFFIC_ID_APP_TOR = {
    # AIM Chat
    'tor_chat_aimchatgateway': 0,
    'tor_chat_gate_aim_chat': 1,
    # Email
    'tor_mail_gate_email_imap_filetransfer': 2,
    # Facebook
    'tor_voip_gate_facebook_audio': 3,
    'tor_voip_facebook_voice_gateway': 4,
    'tor_chat_gate_facebook_chat': 5,
    'tor_chat_facebookchatgateway': 6,
    # FTPS 
    'tor_file-transfer_gate_ftp_transfer': 7,
    # Gmail 
    # Hangouts 
    'tor_voip_hangouts_voice_gateway': 8, 
    'tor_voip_gate_hangout_audio': 9,
    'tor_chat_hangoutschatgateway':10,
    'tor_chat_gate_hangout_chat':11,
    # ICQ
    'tor_chat_icqchatgateway': 12,
    'tor_chat_gate_icq_chat': 13, 
    # Netflix 
    # SCP
    # SFTP
    'tor_file-transfer_gate_sftp_filetransfer': 14,
    # Skype 
    'tor_voip_skype_voice_gateway': 15,
    'tor_voip_gate_skype_audio':16,
    'tor_file-transfer_tor_skype_transfer':17,
    'tor_chat_skypechatgateway':18,
    'tor_chat_gate_skype_chat':19,
    # Spotify
    'tor_audio_spotifygateway':20,
    'tor_audio_tor_spotify':21,
    'tor_audio_tor_spotify2':22,
    'tor_tor_spotify2-1' :23,
    'tor_tor_spotify2-2':24,
    # Torrent 
    # Tor
    # VoipBuster 
    # Vimeo 
    'tor_video_vimeo_gateway':25,
    # YouTube
    'tor_video_youtube_html5_gateway':26,
    'tor_video_youtube_flash_gateway': 27,

   
}

PREFIX_TO_TRAFFIC_ID_APP_NONVPN = {
    # AIM Chat
    'aimchat1': 0,
    'aimchat2': 1,
    'aim_chat_3a': 2,
    'aim_chat_3b': 3,
    'aim_chat': 4,
    'aimchat': 5,
    # Email
    'email1a': 6,
    'email1b': 7,
    'email2a': 8,
    'email2b': 9,
    'email_imap_filetransfer': 10,
    # Facebook
    'facebook_audio1a': 11,
    'facebook_audio1b': 12,
    'facebook_audio2a': 13,
    'facebook_audio2b': 14,
    'facebook_audio3': 15,
    'facebook_audio4': 16,
    'facebookchat1': 17,
    'facebookchat2': 18,
    'facebookchat3': 19,
    'facebook_chat_4a': 20,
    'facebook_chat_4b': 21,
    'facebook_video1a': 22,
    'facebook_video1b': 23,
    'facebook_video2a': 24,
    'facebook_video2b': 25,
    'facebook_audio': 26,
    'facebook_chat': 27,
    'facebook_voice_workstation': 28,
    'facebookchat': 29,
    # FTPS 
    'ftps_down_1a': 30,
    'ftps_down_1b': 31,
    'ftps_up_2a': 32,
    'ftps_up_2b': 33,
    'ftp_filetransfer': 34,
    # Gmail 
    'gmailchat1': 35,
    'gmailchat2': 36,
    'gmailchat3': 37,
    # Hangouts 
    'hangouts_audio1a': 38,
    'hangouts_audio1b': 39,
    'hangouts_audio2a': 40,
    'hangouts_audio2b': 41,
    'hangouts_audio3': 42,
    'hangouts_audio4': 43,
    'hangouts_chat_4a': 44,
    'hangout_chat_4b': 45,
    'hangouts_video1b': 46,
    'hangouts_video2a': 47,
    'hangouts_video2b': 48,
    'hangout_audio': 49,
    'hangout_chat': 50,
    'hangouts_voice_workstation': 51,
    'hangoutschat': 52,
    # ICQ
    'icqchat1': 53,
    'icqchat2': 54, 
    'icq_chat_3a': 55, 
    'icq_chat_3b': 56,
    'icq_chat': 57,
    'icqchat': 58,
    # Netflix 
    'netflix1': 59,
    'netflix2': 60,
    'netflix3': 61,
    'netflix4': 62,
    # SCP
    'scp1':63,
    'scpdown1': 64,
    'scpdown2': 65,
    'scpdown3': 66,
    'scpdown4': 67,
    'scpdown5': 68,
    'scpdown6': 69,
    'scpup1': 70,
    'scpup2': 71,
    'scpup3': 72,
    'scpup5': 73,
    'scpup6': 74,
    # SFTP
    'sftp1': 75,
    'sftpdown1': 76,
    'sftpdown2': 77,
    'sftp_down_3a': 78,
    'sftp_down_3b': 79,
    'sftpup1': 80, 
    'sftp_up_2a': 81,
    'sftp_up_2b': 82,
    'sftp_filetransfer': 83,
    # Skype 
    'skype_audio1a': 84,
    'skype_audio1b': 85,
    'skype_audio2a': 86,
    'skype_audio2b': 87,
    'skype_audio3': 88,
    'skype_audio4': 89,
    'skype_chat1a': 90,
    'skype_chat1b': 91,
    'skype_file1': 92,
    'skype_file2': 93,
    'skype_file3': 94,
    'skype_file4': 95,
    'skype_file5': 96,
    'skype_file6': 97,
    'skype_file7': 98,
    'skype_file8': 99,
    'skype_video1a': 100,
    'skype_video1b': 101,
    'skype_video2a': 102,
    'skype_video2b': 103,
    'skype_audio': 104,
    'skype_chat': 105,
    'skype_transfer': 106,
    'skype_voice_workstation': 107,
    'skypechat': 108,
    # Spotify 
    'spotify1': 109,
    'spotify2': 110,
    'spotify3': 111,
    'spotify4': 112,
    'spotify': 113,
    'spotify2-1': 114,
    'spotify2-2': 115,
    'spotify2': 116,
    'spotifyandrew': 117,
    # Torrent 
    'torrent01': 118,
    # Tor
    'torfacebook': 119,
    'torgoogle': 120,
    'tortwitter': 121,
    'torvimeo1': 122,
    'torvimeo2': 123,
    'torvimeo3': 124,
    'toryoutube1': 125,
    'toryoutube2': 126,
    'toryoutube3': 127,
    # VoipBuster 
    'voipbuster1b': 128,
    'voipbuster2b': 129,
    'voipbuster3b': 130,
    'voipbuster_4a': 131,
    'voipbuster_4b': 132,
    # Vimeo 
    'vimeo1': 133,
    'vimeo2': 134,
    'vimeo3': 135,
    'vimeo4': 136,
    'vimeo_workstation': 137,
    # YouTube
    'youtube1': 138,
    'youtube2': 139,
    'youtube3': 140,
    'youtube4': 141,
    'youtube5': 142,
    'youtube6': 143,
    'youtubehtml5_1': 144,
    'youtube_flash_workstation': 145,
    'youtube_html5_workstation': 146
}


ID_TO_TRAFFIC_APP ={
    0: 'AIM chat',
    1: 'Email',
    2: 'Facebook',
    3: 'FTPS',
    4: 'Gmail',
    5: 'Hangouts',
    6: 'ICQ',
    7: 'Netflix',
    8: 'SCP',
    9: 'SFTP',
    10: 'Skype',
    11: 'Spotify',
    12: 'Torrent',
    13: 'Tor',
    14: 'VoipBuster',
    15: 'Vimeo',
    16: 'YouTube',
}


"""
PREFIX_TO_TRAFFIC_ID_APP_NONVPN = {
    # Facebook Voip
    # 'facebook_audio1a': 0,
    # 'facebook_audio1b': 1,
    # 'facebook_audio2a': 2,
    # 'facebook_audio2b': 3,
    # 'facebook_audio3': 4,
    # 'facebook_audio4': 5,
    'tor_voip_facebook_voice_gateway':5,
    'tor_voip_gate_facebook_audio': 6,
    # 'tor_voip_facebook_voice_gateway':'0',
    #Hangouts Voip
    # 'hangouts_audio1a': 7,
    # 'hangouts_audio1b': 8,
    # 'hangouts_audio2a': 9,
    # 'hangouts_audio2b': 10,
    # 'hangouts_audio3': 11,
    # 'hangouts_audio4': 12,
    'hangout_audio': 13,
    #Skype Voip
    # 'skype_audio1a': 14,
    # 'skype_audio1b': 15,
    # 'skype_audio2a': 16,
    # 'skype_audio2b': 17,
    # 'skype_audio3': 18,
    # 'skype_audio4': 19,
    'skype_audio': 20,
    # VoipBuster 
    'voipbuster1b': 21,
    'voipbuster2b': 22,
    'voipbuster3b': 23,
    'voipbuster_4a': 24,
    'voipbuster_4b': 25,
    # Facebook Video
    'facebook_video1a': 26,
    'facebook_video1b': 27,
    'facebook_video2a': 28,
    'facebook_video2b': 29,
    # Hangouts Video
    'hangouts_video1b': 30,
    'hangouts_video2a': 31,
    'hangouts_video2b': 32,
    # Netflix 
    'netflix1': 33,
    'netflix2': 34,
    'netflix3': 35,
    'netflix4': 36,
    # Skype Video
    'skype_video1a': 37,
    'skype_video1b': 38,
    'skype_video2a': 39,
    'skype_video2b': 40,
    # Vimeo 
    'vimeo1': 41,
    'vimeo2': 42,
    'vimeo3': 43,
    'vimeo4': 44,
    # 'vimeo_workstation': 45,
    # YouTube
    'youtube1': 46,
    'youtube2': 47,
    'youtube3': 48,
    'youtube4': 49,
    'youtube5': 50,
    'youtube6': 51,
    'youtubehtml5_1': 52,
    # 'youtube_flash_workstation': 53,
    # 'youtube_html5_workstation': 54
}
"""

"""
ID_TO_TRAFFIC_APP ={
    0: 'Facebook Voip',
    1: 'Hangouts Voip',
    2: 'Skype Voip',
    3: 'VoipBuster',
    4: 'Facebook Video',
    5: 'Hangouts Video',
    6: 'Netflix',
    7: 'Skype Video',
    8: 'Vimeo',
    9: 'YouTube',
}
"""


def read_pcap(path:Path): #返回pcap文件中的所有包
    packets = rdpcap(str(path))
    return packets

def should_omit_packet(packet):
    #0x10ACK，0x02SYN，0x01FIN
    #判断是否是ACK，SYN，FIN包并且没有payload
    
    #传输层协议为TCP且整个会话握手信息不完整或者没有业务载荷
    if TCP in packet and (packet.flags & 0x13):
        layers = packet[TCP].payload.layers()
        #两个判断条件的，第一个判断如果没有payload直接通过
        #第二个判断条件，如果有payload但是是padding也直接通过
        if not layers or (Padding in layers and len(layers) == 1):
            # print("layers:"+str(not layers))
            # print("layer length:"+str(len(layers)))
            #print(1)
            # print("_____________________")
            return True

    # DNS segment
    if DNS in packet:
        #print(1)
        return True

    #print(0)
    return False

# packets = read_pcap('ftp_web.pcap')
# i = 1
# for packet in packets:
#     print(i)
#     i = i+1
#     should_omit_packet(packet)