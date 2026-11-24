"""
schema.py
=========
Single source of truth for dataset column names and feature lists.

Every other backend module (features.py, detector.py, train_model.py) and
the frontend (app.py) import from here. This guarantees the feature names
and their order can never drift apart between training and live detection,
which is the most common source of bugs in ML-based NIDS projects.
"""

# The 41 features of the NSL-KDD dataset, in file order. The raw .txt files
# have no header row, so this list is supplied manually when loading them.
FEATURES_FULL = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent",
    "hot", "num_failed_logins", "logged_in", "num_compromised", "root_shell",
    "su_attempted", "num_root", "num_file_creations", "num_shells",
    "num_access_files", "num_outbound_cmds", "is_host_login", "is_guest_login",
    "count", "srv_count", "serror_rate", "srv_serror_rate", "rerror_rate",
    "srv_rerror_rate", "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
    "dst_host_count", "dst_host_srv_count", "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate", "dst_host_serror_rate",
    "dst_host_srv_serror_rate", "dst_host_rerror_rate", "dst_host_srv_rerror_rate",
]

# Full layout of the raw KDDTrain+.txt / KDDTest+.txt files.
COLUMNS = FEATURES_FULL + ["label", "difficulty"]

# Categorical columns that need one-hot encoding.
CATEGORICAL = ["protocol_type", "service", "flag"]

# --------------------------------------------------------------------------
# Features a packet sniffer can realistically compute from raw traffic.
# This is the ONLY feature set the deployed model is allowed to use.
# Order matters: it is the exact input order the saved model expects.
# See backend/features.py for how each one is computed from packets.
# --------------------------------------------------------------------------
FEATURES_LIVE = [
    "duration", "protocol_type", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent",
    "count", "srv_count", "serror_rate", "rerror_rate",
    "same_srv_rate", "diff_srv_rate",
]

# Attack-name -> attack-family mapping, used for the optional multiclass model.
ATTACK_FAMILY = {"normal": "normal"}
_FAMILY_MEMBERS = {
    "DoS":   "back land neptune pod smurf teardrop mailbomb apache2 processtable udpstorm",
    "Probe": "ipsweep nmap portsweep satan mscan saint",
    "R2L":   ("ftp_write guess_passwd imap multihop phf spy warezclient warezmaster "
              "sendmail named snmpgetattack snmpguess xlock xsnoop worm"),
    "U2R":   "buffer_overflow loadmodule perl rootkit httptunnel ps sqlattack xterm",
}
for _family, _names in _FAMILY_MEMBERS.items():
    for _name in _names.split():
        ATTACK_FAMILY[_name] = _family
