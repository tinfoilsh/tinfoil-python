from dataclasses import dataclass
from enum import IntEnum

POLICY_RESERVED_1_BIT = 17
REPORT_SIZE = 0x4A0  # 1184 bytes
SIGNATURE_OFFSET = 0x2A0
ECDSA_RS_SIZE = 72
ECDSA_P384_SHA384_SIGNATURE_SIZE = ECDSA_RS_SIZE + ECDSA_RS_SIZE

ZEN3ZEN4_FAMILY = 0x19
ZEN5_FAMILY     = 0x1A
MILAN_MODEL     = 0 | 1
GENOA_MODEL     = (1 << 4) | 1
TURIN_MODEL     = 2

class ReportSigner(IntEnum):
    VcekReportSigner = 0
	# VlekReportSigner is the SIGNING_KEY value for if the VLEK signed the attestation report.
    VlekReportSigner = 1
    endorseReserved2 = 2
    endorseReserved3 = 3
    endorseReserved4 = 4
    endorseReserved5 = 5
    endorseReserved6 = 6
    # NoneReportSigner is the SIGNING_KEY value for if the attestation report is not signed.
    NoneReportSigner = 7
        
# SignerInfo represents information about the signing circumstances for the attestation report.
class SignerInfo:
	# SigningKey represents kind of key by which a report was signed.
	signingKey: ReportSigner
	# MaskChipKey is true if the host chose to enable CHIP_ID masking, to cause the report's CHIP_ID
	# to be all zeros.
	maskChipKey: bool
	# AuthorKeyEn is true if the VM is launched with an IDBLOCK that includes an author key.
	authorKeyEn: bool

@dataclass
class TCBParts:
    """Represents the decomposed parts of a TCB version"""
    ucode_spl: int
    snp_spl: int
    spl7: int
    spl6: int
    spl5: int
    spl4: int
    tee_spl: int
    bl_spl: int

def DecomposeTCBVersion(tcb: int) -> TCBParts:
    """Decompose a TCB version into its constituent parts"""
    return TCBParts(
        ucode_spl=((tcb >> 56) & 0xff),
        snp_spl=((tcb >> 48) & 0xff),
        spl7=((tcb >> 40) & 0xff),
        spl6=((tcb >> 32) & 0xff),
        spl5=((tcb >> 24) & 0xff),
        spl4=((tcb >> 16) & 0xff),
        tee_spl=((tcb >> 8) & 0xff),
        bl_spl=((tcb >> 0) & 0xff)
    )

@dataclass 
class Report:
    """SEV-SNP attestation report"""
    version: int  # Should be 2 for revision 1.55, and 3 for revision 1.56
    guest_svn: int
    policy: int
    family_id: bytes  # Should be 16 bytes long
    image_id: bytes   # Should be 16 bytes long
    vmpl: int
    signature_algo: int
    current_tcb: int
    platform_info: int
    signer_info: int  # AuthorKeyEn, MaskChipKey, SigningKey
    signer_info_parsed: SignerInfo
    report_data: bytes  # Should be 64 bytes long
    measurement: bytes  # Should be 48 bytes long
    host_data: bytes   # Should be 32 bytes long
    id_key_digest: bytes  # Should be 48 bytes long
    author_key_digest: bytes  # Should be 48 bytes long
    report_id: bytes   # Should be 32 bytes long
    report_id_ma: bytes  # Should be 32 bytes long
    reported_tcb: int
    chip_id: bytes  # Should be 64 bytes long
    committed_tcb: int
    current_build: int
    current_minor: int
    current_major: int
    committed_build: int
    committed_minor: int
    committed_major: int
    launch_tcb: int
    signed_data: bytes
    signature: bytes  # Should be 512 bytes long
    cpuid1eax_fms: int  # The cpuid(1).eax & 0x0fff0fff representation of family/model/stepping
    family: bytes
    model: bytes
    stepping: bytes
    productName: str

    def __init__(self, data: bytes):
        """
        Parse an attestation report from raw bytes in SEV SNP ABI format.
        
        Args:
            data: Raw bytes of the attestation report
        Returns:
            Report object containing parsed data
        """

        if len(data) < REPORT_SIZE:
            raise ValueError(f"Array size is 0x{len(data):x}, an SEV-SNP attestation report size is 0x{REPORT_SIZE:x}")

        # Parse all fields using little-endian byte order
        self.version = int.from_bytes(data[0x00:0x04], byteorder='little')
        self.guest_svn = int.from_bytes(data[0x04:0x08], byteorder='little')
        self.policy = int.from_bytes(data[0x08:0x10], byteorder='little')
        
        # Check reserved bit must be 1
        if not (self.policy & (1 << POLICY_RESERVED_1_BIT)):
            raise ValueError(f"policy[{POLICY_RESERVED_1_BIT}] is reserved, must be 1, got 0")
        
        # Check bits 63-21 must be zero
        if self.policy >> 21:
            raise ValueError("policy bits 63-21 must be zero")
    
        self.family_id = data[0x10:0x20]  # 16 bytes
        self.image_id = data[0x20:0x30]   # 16 bytes
        self.vmpl = int.from_bytes(data[0x30:0x34], byteorder='little')
        self.signature_algo = int.from_bytes(data[0x34:0x38], byteorder='little')
        self.current_tcb = int.from_bytes(data[0x38:0x40], byteorder='little')
        self.platform_info = int.from_bytes(data[0x40:0x48], byteorder='little')
        self.signer_info = int.from_bytes(data[0x48:0x4C], byteorder='little')

        self.signer_info_parsed = SignerInfo()
        try:
            mbz64(int(self.signer_info), "signer_info", 31, 5)
        except ValueError as e:
            raise ValueError(f"signer_info not correctly formed: {e}")
        
        self.signer_info_parsed.signingKey = ReportSigner((self.signer_info >> 2) & 7)
        if self.signer_info_parsed.signingKey != ReportSigner.VcekReportSigner:
            raise ValueError(f"This implementation only supports VCEK signed reports. Got {self.signer_info_parsed.signingKey}")
        self.signer_info_parsed.maskChipKey = (self.signer_info & 2) != 0
        self.signer_info_parsed.authorKeyEn = (self.signer_info & 1) != 0

        try:
            mbz(data, 0x4C, 0x50)
        except ValueError as e:
            raise ValueError(f"report_data not correctly formed: {e}")

        # 0x4C-0x50 is MBZ (Must Be Zero)
        self.report_data = data[0x50:0x90]      # 64 bytes
        self.measurement = data[0x90:0xC0]       # 48 bytes
        self.host_data = data[0xC0:0xE0]        # 32 bytes
        self.id_key_digest = data[0xE0:0x110]    # 48 bytes
        self.author_key_digest = data[0x110:0x140]  # 48 bytes
        self.report_id = data[0x140:0x160]       # 32 bytes
        self.report_id_ma = data[0x160:0x180]    # 32 bytes
        self.reported_tcb = int.from_bytes(data[0x180:0x188], byteorder='little')
        
        mbzLo = 0x188
        # Version specific parsing
        if self.version == 3:  # Report Version 3
            self.family = data[0x188]
            self.model = data[0x189]
            self.stepping = data[0x18A]
            self._init_product_name()
            mbzLo = 0x18B
        elif self.version == 2:  # Report Version 2
            self.productName = "Genoa"
            # TODO impose default for now with genoa
        else:
            raise ValueError("Unknown report version")
        
        try:
            mbz(data, mbzLo, 0x1A0)
        except ValueError as e:
            raise ValueError(f"report_data not correctly formed: {e}")
        
        self.chip_id = data[0x1A0:0x1E0]        # 64 bytes
        self.committed_tcb = int.from_bytes(data[0x1E0:0x1E8], byteorder='little')
        
        # Version fields
        self.current_build = data[0x1E8]
        self.current_minor = data[0x1E9]
        self.current_major = data[0x1EA]

        try:
            mbz(data, 0x1EB, 0x1EC)
        except ValueError as e:
            raise ValueError(f"report_data not correctly formed: {e}")
        
        self.committed_build = data[0x1EC]
        self.committed_minor = data[0x1ED]
        self.committed_major = data[0x1EE]
        
        try:
            mbz(data, 0x1EF, 0x1F0)
        except ValueError as e:
            raise ValueError(f"report_data not correctly formed: {e}")
        
        self.launch_tcb = int.from_bytes(data[0x1F0:0x1F8], byteorder='little')

        try:
            mbz(data, 0x1F8, SIGNATURE_OFFSET)
        except ValueError as e:
            raise ValueError(f"report_data not correctly formed: {e}")
        
        if self.signature_algo == 1: # ECDSA P-384 SHA-384
            try:
                mbz(data, SIGNATURE_OFFSET+ECDSA_P384_SHA384_SIGNATURE_SIZE, REPORT_SIZE)
            except ValueError as e:
                raise ValueError(f"report_data not correctly formed: {e}")
        
        self.signed_data = data[0:SIGNATURE_OFFSET]
        self.signature = data[SIGNATURE_OFFSET:REPORT_SIZE]
        
    def get_fms(self):
        return self.family, self.model, self.stepping
    
    def _init_product_name(self):
        # Combined extended values
        self.productName = "Unknown"
        if self.family == ZEN3ZEN4_FAMILY:
            if self.model == MILAN_MODEL:
                self.productName = "Milan"
            elif self.model == GENOA_MODEL:
                self.productName = "Genoa"
        elif self.family == ZEN5_FAMILY:
            if self.model == TURIN_MODEL:
                self.productName = "Turin"

## HELPER FUNCTIONS
    
def find_non_zero(data: bytes, lo: int, hi: int) -> int:
    """
    Returns the first index which is not zero, otherwise returns hi.
    
    Args:
        data: Bytes object to search through
        lo: Starting index (inclusive)
        hi: Ending index (exclusive)
    Returns:
        Index of first non-zero byte, or hi if all bytes are zero
    """
    for i in range(lo, hi):
        if data[i] != 0:
            return i
    return hi

def mbz(data: bytes, lo: int, hi: int) -> None:
    """
    Checks if a range of bytes is all zeros.
    
    Args:
        data: Bytes object to check
        lo: Starting index (inclusive)
        hi: Ending index (exclusive)
    Raises:
        ValueError: If any byte in the range is non-zero
    """
    first_non_zero = find_non_zero(data, lo, hi)
    if first_non_zero != hi:
        # Convert the slice to hex string for error message
        hex_str = data[lo:hi].hex()
        raise ValueError(f"mbz range [0x{lo:x}:0x{hi:x}] not all zero: {hex_str}")

def mbz64(data: int, base: str, hi: int, lo: int) -> None:
    """
    Checks if a range of bits in an integer is all zeros.
    
    Args:
        data: Integer to check
        base: String identifier for error message
        hi: Highest bit position (inclusive)
        lo: Lowest bit position (inclusive)
    Raises:
        ValueError: If any bit in the range is non-zero
    """
    # Create mask for the bit range
    mask = (1 << (hi - lo + 1)) - 1
    # Extract and check the bits
    bits = (data >> lo) & mask
    if bits != 0:
        raise ValueError(f"mbz range {base}[0x{lo:x}:0x{hi:x}] not all zero: {hex(data)}")
    