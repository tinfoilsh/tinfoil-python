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
    tee_spl: int
    bl_spl: int

    def __str__(self) -> str:
        """Return a human-friendly string with all component SPL values."""
        # Print fields in order starting with the least-significant component (bl_spl)
        return (
            "TCBParts("  # Opening
            f"bl_spl=0x{self.bl_spl:02x}, "
            f"tee_spl=0x{self.tee_spl:02x}, "
            f"snp_spl=0x{self.snp_spl:02x}, "
            f"ucode_spl=0x{self.ucode_spl:02x})"
        )

    @classmethod
    def from_int(cls, tcb: int) -> "TCBParts":
        """Build a TCBParts instance from a 64-bit packed TCB value."""
        return cls(
            ucode_spl=((tcb >> 56) & 0xff),
            snp_spl=((tcb >> 48) & 0xff),
            tee_spl=((tcb >> 8) & 0xff),
            bl_spl=((tcb >> 0) & 0xff),
        )

    def meets_minimum(self, minimum: "TCBParts") -> bool:
        """Check if this TCB meets minimum requirements (component-wise)."""
        return (
            self.bl_spl >= minimum.bl_spl and
            self.tee_spl >= minimum.tee_spl and
            self.snp_spl >= minimum.snp_spl and
            self.ucode_spl >= minimum.ucode_spl
        )

@dataclass
class SnpPlatformInfo:
    """Decoded view of the 64-bit PLATFORM_INFO field."""

    smt_enabled: bool
    tsme_enabled: bool
    ecc_enabled: bool
    rapl_disabled: bool
    ciphertext_hiding_dram_enabled: bool
    alias_check_complete: bool
    tio_enabled: bool

    @classmethod
    def from_int(cls, value: int) -> "SnpPlatformInfo":
        return cls(
            smt_enabled=bool(value & (1 << 0)),
            tsme_enabled=bool(value & (1 << 1)),
            ecc_enabled=bool(value & (1 << 2)),
            rapl_disabled=bool(value & (1 << 3)),
            ciphertext_hiding_dram_enabled=bool(value & (1 << 4)),
            alias_check_complete=bool(value & (1 << 5)),
            tio_enabled=bool(value & (1 << 7))
        )

    def __str__(self) -> str:  # pragma: no cover – formatting helper
        return (
            "SnpPlatformInfo("  # opening
            f"SMTEnabled={self.smt_enabled}, "
            f"TSMEEnabled={self.tsme_enabled}, "
            f"ECCEnabled={self.ecc_enabled}, "
            f"RAPLDisabled={self.rapl_disabled}, "
            f"CiphertextHidingDRAMEnabled={self.ciphertext_hiding_dram_enabled}, "
            f"AliasCheckComplete={self.alias_check_complete}, "
            f"TIOEnabled={self.tio_enabled})"
        )


@dataclass
class SnpPolicy:
    """Decoded view of the 64-bit POLICY field (bits 0-20)."""

    abi_minor: int
    abi_major: int
    smt: bool
    migrate_ma: bool
    debug: bool
    single_socket: bool
    cxl_allowed: bool
    mem_aes256_xts: bool
    rapl_dis: bool
    ciphertext_hiding_dram: bool
    page_swap_disabled: bool

    def __str__(self) -> str:  # pragma: no cover – formatting helper
        return (
            "SnpPolicy("  # opening
            f"ABIMajor={self.abi_major}, ABIMinor={self.abi_minor}, "
            f"SMT={self.smt}, MigrateMA={self.migrate_ma}, Debug={self.debug}, "
            f"SingleSocket={self.single_socket}, CXLAllowed={self.cxl_allowed}, "
            f"MemAES256XTS={self.mem_aes256_xts}, RAPLDis={self.rapl_dis}, "
            f"CipherTextHidingDRAM={self.ciphertext_hiding_dram}, PageSwapDisabled={self.page_swap_disabled})"
        )

    @classmethod
    def from_int(cls, value: int) -> "SnpPolicy":
        """Parse the guest policy bit-field following AMD SEV-SNP spec."""
        return cls(
            abi_minor=value & 0xFF,
            abi_major=(value >> 8) & 0xFF,
            smt=bool(value & (1 << 16)),
            migrate_ma=bool(value & (1 << 18)),
            debug=bool(value & (1 << 19)),
            single_socket=bool(value & (1 << 20)),
            cxl_allowed=bool(value & (1 << 21)),
            mem_aes256_xts=bool(value & (1 << 22)),
            rapl_dis=bool(value & (1 << 23)),
            ciphertext_hiding_dram=bool(value & (1 << 24)),
            page_swap_disabled=bool(value & (1 << 25)),
        )

@dataclass 
class Report:
    """SEV-SNP attestation report"""
    version: int  # Should be 2 for revision 1.55, 3 for revision 1.56, 5 for revision 1.58
    guest_svn: int
    policy: int
    policy_parsed: SnpPolicy
    family_id: bytes  # Should be 16 bytes long
    image_id: bytes   # Should be 16 bytes long
    vmpl: int
    signature_algo: int
    current_tcb: int
    platform_info: int
    platform_info_parsed: SnpPlatformInfo
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
        
        # Check bits 63-26 must be zero
        if self.policy >> 26:
            raise ValueError("policy bits 63-26 must be zero")
    
        self.family_id = data[0x10:0x20]  # 16 bytes
        self.image_id = data[0x20:0x30]   # 16 bytes
        self.vmpl = int.from_bytes(data[0x30:0x34], byteorder='little')
        self.signature_algo = int.from_bytes(data[0x34:0x38], byteorder='little')
        self.current_tcb = int.from_bytes(data[0x38:0x40], byteorder='little')

        try:
            mbz64(int(self.current_tcb), "current_tcb", 47, 16)
        except ValueError as e:
            raise ValueError(f"current_tcb not correctly formed: {e}")
        
        self.platform_info = int.from_bytes(data[0x40:0x48], byteorder='little')
        # Decode additional helper structures for easier consumption later.
        self.policy_parsed = SnpPolicy.from_int(self.policy)
        self.platform_info_parsed = SnpPlatformInfo.from_int(self.platform_info)
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

        try:
            mbz64(int(self.reported_tcb), "reported_tcb", 47, 16)
        except ValueError as e:
            raise ValueError(f"reported_tcb not correctly formed: {e}")

        mbzLo = 0x188
        # Version specific parsing
        if self.version >= 3:  # Report Version 3
            self.family = data[0x188]
            self.model = data[0x189]
            self.stepping = data[0x18A]
            self._init_product_name()
            mbzLo = 0x18B
        elif self.version == 2:  # Report Version 2
            self.family = ZEN3ZEN4_FAMILY
            self.model = GENOA_MODEL
            self.stepping = 0x01
            self.productName = "Genoa"
        else:
            raise ValueError("Unknown report version")
        
        try:
            mbz(data, mbzLo, 0x1A0)
        except ValueError as e:
            raise ValueError(f"report_data not correctly formed: {e}")
        
        self.chip_id = data[0x1A0:0x1E0]        # 64 bytes
        self.committed_tcb = int.from_bytes(data[0x1E0:0x1E8], byteorder='little')

        try:
            mbz64(int(self.committed_tcb), "committed_tcb", 47, 16)
        except ValueError as e:
            raise ValueError(f"committed_tcb not correctly formed: {e}")
        
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
            mbz64(int(self.launch_tcb), "launch_tcb", 47, 16)
        except ValueError as e:
            raise ValueError(f"launch_tcb not correctly formed: {e}")

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

    def print_report(self):
        """Print all relevant fields of the SEV-SNP attestation report in a human-readable format."""
        print("=== SEV-SNP Attestation Report ===")
        print(f"Version: {self.version}")
        print(f"Guest SVN: {self.guest_svn}")
        print(f"Policy: 0x{self.policy:x}")
        print(f"  -> {self.policy_parsed}")
        print(f"Family ID: {self.family_id.hex()}")
        print(f"Image ID: {self.image_id.hex()}")
        print(f"VMPL: {self.vmpl}")
        print(f"Signature Algorithm: {self.signature_algo}")
        print(f"Current TCB: 0x{self.current_tcb:x}")
        print(f"  -> {TCBParts.from_int(self.current_tcb)}")
        print(f"Platform Info: 0x{self.platform_info:x}")
        print(f"  -> {self.platform_info_parsed}")
        print(f"Signer Info: 0x{self.signer_info:x}")
        print(f"  - Signing Key: {self.signer_info_parsed.signingKey}")
        print(f"  - Mask Chip Key: {self.signer_info_parsed.maskChipKey}")
        print(f"  - Author Key Enabled: {self.signer_info_parsed.authorKeyEn}")
        print(f"Report Data: {self.report_data.hex()}")
        print(f"Measurement: {self.measurement.hex()}")
        print(f"Host Data: {self.host_data.hex()}")
        print(f"ID Key Digest: {self.id_key_digest.hex()}")
        print(f"Author Key Digest: {self.author_key_digest.hex()}")
        print(f"Report ID: {self.report_id.hex()}")
        print(f"Report ID MA: {self.report_id_ma.hex()}")
        print(f"Reported TCB: 0x{self.reported_tcb:x}")
        print(f"  -> {TCBParts.from_int(self.reported_tcb)}")
        print(f"Chip ID: {self.chip_id.hex()}")
        print(f"Committed TCB: 0x{self.committed_tcb:x}")
        print(f"  -> {TCBParts.from_int(self.committed_tcb)}")
        print(f"Current Version: {self.current_major}.{self.current_minor}.{self.current_build}")
        print(f"Committed Version: {self.committed_major}.{self.committed_minor}.{self.committed_build}")
        print(f"Launch TCB: 0x{self.launch_tcb:x}")
        print(f"  -> {TCBParts.from_int(self.launch_tcb)}")
        print(f"Product Name: {self.productName}")
        if hasattr(self, 'family') and hasattr(self, 'model') and hasattr(self, 'stepping'):
            print(f"CPU: Family=0x{self.family:02x}, Model=0x{self.model:02x}, Stepping=0x{self.stepping:02x}")
        print(f"Signature Length: {len(self.signature)} bytes")
        print("=" * 40)

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
    
