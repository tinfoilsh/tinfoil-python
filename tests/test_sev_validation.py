import pytest
from tinfoil.attestation.validate import (
    ValidationOptions, 
    validate_report, 
    _validate_policy, 
    _compare_policy_versions, 
    _validate_platform_info
)
from tinfoil.attestation.abi_sevsnp import (
    Report, 
    SnpPolicy, 
    SnpPlatformInfo, 
    TCBParts,
    SignerInfo,
    ReportSigner
)
from tinfoil.attestation.verify import CertificateChain


class TestValidationOptions:
    """Test the ValidationOptions dataclass"""
    
    def test_default_values(self):
        """Test that ValidationOptions has correct default values"""
        options = ValidationOptions()
        
        # Policy / version constraints
        assert options.guest_policy is None
        assert options.minimum_guest_svn is None
        assert options.minimum_build is None
        assert options.minimum_version is None
        
        # TCB requirements
        assert options.minimum_tcb is None
        assert options.minimum_launch_tcb is None
        assert options.permit_provisional_firmware == False
        
        # Field equality checks
        assert options.report_data is None
        assert options.host_data is None
        assert options.image_id is None
        assert options.family_id is None
        assert options.report_id is None
        assert options.report_id_ma is None
        assert options.measurement is None
        assert options.chip_id is None
        
        # Misc
        assert options.platform_info is None
        assert options.vmpl is None
        
        # ID-block / author key requirements
        assert options.require_author_key == False
        assert options.require_id_block == False

    def test_custom_values(self):
        """Test creating ValidationOptions with custom values"""
        policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=True, migrate_ma=False,
            debug=False, single_socket=True, cxl_allowed=False,
            mem_aes256_xts=True, rapl_dis=True, ciphertext_hiding_dram=True,
            page_swap_disabled=False
        )
        
        tcb = TCBParts(bl_spl=7, tee_spl=0, snp_spl=14, ucode_spl=71)
        
        platform_info = SnpPlatformInfo(
            smt_enabled=True, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=True, ciphertext_hiding_dram_enabled=True,
            alias_check_complete=True, tio_enabled=False
        )
        
        options = ValidationOptions(
            guest_policy=policy,
            minimum_guest_svn=5,
            minimum_build=21,
            minimum_version=355,  # 1.99
            minimum_tcb=tcb,
            minimum_launch_tcb=tcb,
            permit_provisional_firmware=False,
            report_data=b"A" * 64,
            host_data=b"B" * 32,
            image_id=b"C" * 16,
            family_id=b"D" * 16,
            report_id=b"E" * 32,
            report_id_ma=b"F" * 32,
            measurement=b"G" * 48,
            chip_id=b"H" * 64,
            platform_info=platform_info,
            vmpl=1,
            require_author_key=True,
            require_id_block=True
        )
        
        assert options.guest_policy == policy
        assert options.minimum_guest_svn == 5
        assert options.minimum_build == 21
        assert options.minimum_version == 355
        assert options.minimum_tcb == tcb
        assert options.minimum_launch_tcb == tcb
        assert options.permit_provisional_firmware == False
        assert options.report_data == b"A" * 64
        assert options.host_data == b"B" * 32
        assert options.image_id == b"C" * 16
        assert options.family_id == b"D" * 16
        assert options.report_id == b"E" * 32
        assert options.report_id_ma == b"F" * 32
        assert options.measurement == b"G" * 48
        assert options.chip_id == b"H" * 64
        assert options.platform_info == platform_info
        assert options.vmpl == 1
        assert options.require_author_key == True
        assert options.require_id_block == True


class TestValidatePolicy:
    """Test the _validate_policy helper function"""
    
    def test_valid_policy_match(self):
        """Test policy validation with matching policies"""
        policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=True, migrate_ma=False,
            debug=False, single_socket=True, cxl_allowed=False,
            mem_aes256_xts=True, rapl_dis=True, ciphertext_hiding_dram=True,
            page_swap_disabled=False
        )
        
        # Exact match should pass (no exception raised)
        _validate_policy(policy, policy)  # Should not raise
    
    def test_abi_version_compatibility(self):
        """Test ABI version compatibility checks"""
        report_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        
        # Required version lower than report - should pass
        required_lower = SnpPolicy(
            abi_minor=0, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        _validate_policy(report_policy, required_lower)  # Should not raise
        
        # Required version higher than report - should fail
        required_higher = SnpPolicy(
            abi_minor=2, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="Required ABI version"):
            _validate_policy(report_policy, required_higher)

    def test_unauthorized_capabilities(self):
        """Test rejection of unauthorized capabilities"""
        base_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        
        required_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        
        # Test each unauthorized capability
        # migrate_ma
        report_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=True,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="unauthorized migration agent capability"):
            _validate_policy(report_policy, required_policy)
        
        # debug
        report_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=True, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="unauthorized debug capability"):
            _validate_policy(report_policy, required_policy)
        
        # smt
        report_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=True, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="unauthorized symmetric multithreading"):
            _validate_policy(report_policy, required_policy)
        
        # cxl_allowed
        report_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=True,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="unauthorized CXL capability"):
            _validate_policy(report_policy, required_policy)

    def test_missing_required_restrictions(self):
        """Test rejection when required restrictions are missing"""
        base_report = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        
        # Test each required restriction
        # single_socket
        required_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=True, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="single socket restriction not present"):
            _validate_policy(base_report, required_policy)
        
        # mem_aes256_xts
        required_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=True, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="unauthorized memory encryption mode"):
            _validate_policy(base_report, required_policy)
        
        # rapl_dis
        required_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=True, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="unauthorized RAPL capability"):
            _validate_policy(base_report, required_policy)
        
        # ciphertext_hiding_dram
        required_policy = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=True,
            page_swap_disabled=False
        )
        with pytest.raises(ValueError, match="Ciphertext hiding in DRAM isn't enforced"):
            _validate_policy(base_report, required_policy)


class TestComparePolicyVersions:
    """Test the _compare_policy_versions helper function"""
    
    def test_equal_versions(self):
        """Test comparing equal versions"""
        policy1 = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        policy2 = SnpPolicy(
            abi_minor=1, abi_major=2, smt=True, migrate_ma=True,  # Other fields don't matter
            debug=True, single_socket=True, cxl_allowed=True,
            mem_aes256_xts=True, rapl_dis=True, ciphertext_hiding_dram=True,
            page_swap_disabled=True
        )
        
        assert _compare_policy_versions(policy1, policy2) == 0
        assert _compare_policy_versions(policy2, policy1) == 0
    
    def test_different_major_versions(self):
        """Test comparing different major versions"""
        policy_v1 = SnpPolicy(
            abi_minor=1, abi_major=1, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        policy_v2 = SnpPolicy(
            abi_minor=1, abi_major=2, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        
        assert _compare_policy_versions(policy_v1, policy_v2) < 0  # v1 < v2
        assert _compare_policy_versions(policy_v2, policy_v1) > 0  # v2 > v1
    
    def test_different_minor_versions(self):
        """Test comparing different minor versions with same major"""
        policy_v10 = SnpPolicy(
            abi_minor=0, abi_major=1, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        policy_v11 = SnpPolicy(
            abi_minor=1, abi_major=1, smt=False, migrate_ma=False,
            debug=False, single_socket=False, cxl_allowed=False,
            mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
            page_swap_disabled=False
        )
        
        assert _compare_policy_versions(policy_v10, policy_v11) < 0  # 1.0 < 1.1
        assert _compare_policy_versions(policy_v11, policy_v10) > 0  # 1.1 > 1.0


class TestValidatePlatformInfo:
    """Test the _validate_platform_info helper function"""
    
    def test_exact_match(self):
        """Test platform info validation with exact match"""
        platform_info = SnpPlatformInfo(
            smt_enabled=True, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=True, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=True, tio_enabled=False
        )
        
        _validate_platform_info(platform_info, platform_info)  # Should not raise
    
    def test_unauthorized_features(self):
        """Test rejection of unauthorized platform features"""
        base_required = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        
        # SMT enabled when not allowed
        report_info = SnpPlatformInfo(
            smt_enabled=True, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        with pytest.raises(ValueError, match="Unauthorized platform feature SMT enabled"):
            _validate_platform_info(report_info, base_required)
    
    def test_missing_required_features(self):
        """Test rejection when required platform features are missing"""
        base_report = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        
        # TSME required but not enabled
        required_info = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=True, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        with pytest.raises(ValueError, match="Required platform feature TSME not enabled"):
            _validate_platform_info(base_report, required_info)
        
        # RAPL disabled required but not disabled
        required_info = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=True, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        with pytest.raises(ValueError, match="Required platform feature RAPL not disabled"):
            _validate_platform_info(base_report, required_info)
        
        # Ciphertext hiding required but not enabled
        required_info = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=True,
            alias_check_complete=False, tio_enabled=False
        )
        with pytest.raises(ValueError, match="Required ciphertext hiding in DRAM not enforced"):
            _validate_platform_info(base_report, required_info)
        
        # Alias check required but not complete
        required_info = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=True, tio_enabled=False
        )
        with pytest.raises(ValueError, match="Required memory alias check hasn't been completed"):
            _validate_platform_info(base_report, required_info)

        # ECC  required but not complete
        required_info = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=False, ecc_enabled=True,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        with pytest.raises(ValueError, match="Required platform feature ECC not enabled"):
            _validate_platform_info(base_report, required_info)


def create_mock_report(**kwargs):
    """Create a mock Report object for testing"""
    # Default values
    defaults = {
        'version': 2,
        'guest_svn': 0,
        'policy': (1 << 17),  # Reserved bit set
        'family_id': b'\x00' * 16,
        'image_id': b'\x00' * 16,
        'vmpl': 0,
        'signature_algo': 1,
        'current_tcb': 0x480e000000000007,
        'platform_info': 0,
        'signer_info': 0,
        'report_data': b'\x00' * 64,
        'measurement': b'\x00' * 48,
        'host_data': b'\x00' * 32,
        'id_key_digest': b'\x00' * 48,
        'author_key_digest': b'\x00' * 48,
        'report_id': b'\x00' * 32,
        'report_id_ma': b'\x00' * 32,
        'reported_tcb': 0x480e000000000007,
        'chip_id': b'\x00' * 64,
        'committed_tcb': 0x480e000000000007,
        'current_build': 21,
        'current_minor': 55,
        'current_major': 1,
        'committed_build': 21,
        'committed_minor': 55,
        'committed_major': 1,
        'launch_tcb': 0x480e000000000007,
        'signed_data': b'\x00' * 672,
        'signature': b'\x00' * 512,
        'family': 0x19,
        'model': 0x11,
        'stepping': 0x01,
        'productName': 'Genoa'
    }
    
    # Override with provided kwargs
    defaults.update(kwargs)
    
    # Create mock object
    class MockReport:
        def __init__(self, **attrs):
            for key, value in attrs.items():
                setattr(self, key, value)
            
            # Parse helper structures
            self.policy_parsed = SnpPolicy.from_int(self.policy)
            self.platform_info_parsed = SnpPlatformInfo.from_int(self.platform_info)
            self.signer_info_parsed = SignerInfo()
            self.signer_info_parsed.signingKey = ReportSigner.VcekReportSigner
            self.signer_info_parsed.maskChipKey = False
            self.signer_info_parsed.authorKeyEn = False
    
    return MockReport(**defaults)


class MockCertificateChain:
    """Mock certificate chain for testing"""
    def validate_vcek_tcb(self, tcb):
        pass  # Do nothing for tests
    
    def validate_vcek_hwid(self, chip_id):
        pass  # Do nothing for tests


class TestValidateReport:
    """Test the main validate_report function"""
    
    def test_validate_empty_options(self):
        """Test validation with empty options (should always pass)"""
        report = create_mock_report()
        chain = MockCertificateChain()
        options = ValidationOptions()
        
        validate_report(report, chain, options)  # Should not raise
    
    def test_guest_policy_validation(self):
        """Test guest policy validation"""
        report = create_mock_report(policy=(1 << 17))  # Only reserved bit set
        chain = MockCertificateChain()
        
        # Matching policy should pass
        options = ValidationOptions(
            guest_policy=SnpPolicy.from_int((1 << 17))
        )
        validate_report(report, chain, options)  # Should not raise
        
        # Non-matching policy should fail
        options = ValidationOptions(
            guest_policy=SnpPolicy(
                abi_minor=1, abi_major=2, smt=True, migrate_ma=False,
                debug=False, single_socket=False, cxl_allowed=False,
                mem_aes256_xts=False, rapl_dis=False, ciphertext_hiding_dram=False,
                page_swap_disabled=False
            )
        )
        with pytest.raises(ValueError):
            validate_report(report, chain, options)
    
    def test_minimum_guest_svn(self):
        """Test minimum guest SVN validation"""
        chain = MockCertificateChain()
        report = create_mock_report(guest_svn=5)
        
        # Lower or equal minimum should pass
        options = ValidationOptions(minimum_guest_svn=5)
        validate_report(report, chain, options)  # Should not raise
        
        options = ValidationOptions(minimum_guest_svn=3)
        validate_report(report, chain, options)  # Should not raise
        
        # Higher minimum should fail
        options = ValidationOptions(minimum_guest_svn=10)
        with pytest.raises(ValueError, match="Guest SVN .* is less than minimum required"):
            validate_report(report, chain, options)
    
    def test_minimum_build(self):
        """Test minimum build validation"""
        chain = MockCertificateChain()
        report = create_mock_report(current_build=21, committed_build=21)
        
        # Lower or equal minimum should pass
        options = ValidationOptions(minimum_build=21)
        validate_report(report, chain, options)  # Should not raise
        
        options = ValidationOptions(minimum_build=20)
        validate_report(report, chain, options)  # Should not raise
        
        # Higher minimum should fail
        options = ValidationOptions(minimum_build=25)
        with pytest.raises(ValueError, match="SNP firmware build number .* is less than minimum required"):
            validate_report(report, chain, options)
        
        # Test when current and committed differ (both must meet minimum)
        report = create_mock_report(current_build=25, committed_build=20)
        options = ValidationOptions(minimum_build=22)
        with pytest.raises(ValueError, match="Committed SNP firmware build number .* is less than minimum required"):
            validate_report(report, chain, options)
    
    def test_minimum_version(self):
        """Test minimum version validation"""
        chain = MockCertificateChain()
        # Version 1.55 = (1 << 8) | 55 = 311
        report = create_mock_report(
            current_major=1, current_minor=55,
            committed_major=1, committed_minor=55
        )
        
        # Lower or equal minimum should pass
        options = ValidationOptions(minimum_version=311)  # 1.55
        validate_report(report, chain, options)  # Should not raise
        
        options = ValidationOptions(minimum_version=300)  # 1.44
        validate_report(report, chain, options)  # Should not raise
        
        # Higher minimum should fail
        options = ValidationOptions(minimum_version=320)  # 1.64
        with pytest.raises(ValueError, match="version .* is less than minimum required"):
            validate_report(report, chain, options)
    
    def test_minimum_tcb(self):
        """Test minimum TCB validation"""
        chain = MockCertificateChain()
        # TCB with all components at level 7
        tcb_value = (7 << 56) | (7 << 48) | (7 << 8) | 7
        report = create_mock_report(
            current_tcb=tcb_value,
            committed_tcb=tcb_value,
            reported_tcb=tcb_value
        )
        
        # Lower or equal minimum should pass
        min_tcb = TCBParts(bl_spl=7, tee_spl=7, snp_spl=7, ucode_spl=7)
        options = ValidationOptions(minimum_tcb=min_tcb)
        validate_report(report, chain, options)  # Should not raise
        
        min_tcb = TCBParts(bl_spl=5, tee_spl=5, snp_spl=5, ucode_spl=5)
        options = ValidationOptions(minimum_tcb=min_tcb)
        validate_report(report, chain, options)  # Should not raise
        
        # Higher minimum should fail
        min_tcb = TCBParts(bl_spl=10, tee_spl=10, snp_spl=10, ucode_spl=10)
        options = ValidationOptions(minimum_tcb=min_tcb)
        with pytest.raises(ValueError, match="TCB .* does not meet minimum requirements"):
            validate_report(report, chain, options)
    
    def test_field_equality_checks(self):
        """Test field equality validation"""
        chain = MockCertificateChain()
        report_data = b"A" * 64
        host_data = b"B" * 32
        measurement = b"C" * 48
        
        report = create_mock_report(
            report_data=report_data,
            host_data=host_data,
            measurement=measurement
        )
        
        # Matching fields should pass
        options = ValidationOptions(
            report_data=report_data,
            host_data=host_data,
            measurement=measurement
        )
        validate_report(report, chain, options)  # Should not raise
        
        # Non-matching fields should fail
        options = ValidationOptions(report_data=b"X" * 64)
        with pytest.raises(ValueError, match="Report data mismatch"):
            validate_report(report, chain, options)
        
        options = ValidationOptions(host_data=b"Y" * 32)
        with pytest.raises(ValueError, match="Host data mismatch"):
            validate_report(report, chain, options)
        
        options = ValidationOptions(measurement=b"Z" * 48)
        with pytest.raises(ValueError, match="Measurement mismatch"):
            validate_report(report, chain, options)
    
    def test_vmpl_validation(self):
        """Test VMPL validation"""
        chain = MockCertificateChain()
        report = create_mock_report(vmpl=1)
        
        # Matching VMPL should pass
        options = ValidationOptions(vmpl=1)
        validate_report(report, chain, options)  # Should not raise
        
        # Non-matching VMPL should fail
        options = ValidationOptions(vmpl=2)
        with pytest.raises(ValueError, match="VMPL mismatch"):
            validate_report(report, chain, options)
        
        # Invalid VMPL values should fail
        report = create_mock_report(vmpl=5)  # VMPL > 3
        options = ValidationOptions(vmpl=5)
        with pytest.raises(ValueError, match="VMPL .* is not in valid range"):
            validate_report(report, chain, options)
    
    def test_provisional_firmware_check(self):
        """Test provisional firmware validation"""
        chain = MockCertificateChain()
        # When permit_provisional_firmware=True, should always fail (not supported)
        report = create_mock_report()
        options = ValidationOptions(permit_provisional_firmware=True)
        with pytest.raises(ValueError, match="Provisional firmware is not supported"):
            validate_report(report, chain, options)
        
        # When permit_provisional_firmware=False, committed and current must match
        report = create_mock_report(
            current_build=21, committed_build=21,
            current_minor=55, committed_minor=55,
            current_major=1, committed_major=1,
            current_tcb=0x480e000000000007, committed_tcb=0x480e000000000007
        )
        options = ValidationOptions(permit_provisional_firmware=False)
        validate_report(report, chain, options)  # Should not raise
        
        # Mismatched current/committed should fail
        report = create_mock_report(
            current_build=22, committed_build=21  # Different builds
        )
        with pytest.raises(ValueError, match="Committed build .* does not match current build"):
            validate_report(report, chain, options)
        
        report = create_mock_report(
            current_minor=56, committed_minor=55  # Different minor versions
        )
        with pytest.raises(ValueError, match="Committed minor version .* does not match current minor version"):
            validate_report(report, chain, options)
    
    def test_id_block_author_key_requirements(self):
        """Test ID block and author key requirements"""
        chain = MockCertificateChain()
        report = create_mock_report()
        
        # When require_author_key=True, should fail (not supported)
        options = ValidationOptions(require_author_key=True)
        with pytest.raises(ValueError, match="ID-block and author key requirements are not supported"):
            validate_report(report, chain, options)
        
        # When require_id_block=True, should fail (not supported)
        options = ValidationOptions(require_id_block=True)
        with pytest.raises(ValueError, match="ID-block and author key requirements are not supported"):
            validate_report(report, chain, options)
    
    def test_platform_info_validation(self):
        """Test platform info validation"""
        chain = MockCertificateChain()
        platform_info_value = (1 << 0) | (1 << 3)  # SMT enabled, RAPL disabled
        report = create_mock_report(platform_info=platform_info_value)
        
        # Matching platform info should pass
        expected_info = SnpPlatformInfo(
            smt_enabled=True, tsme_enabled=False, ecc_enabled=False,
            rapl_disabled=True, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        options = ValidationOptions(platform_info=expected_info)
        validate_report(report, chain, options)  # Should not raise
        
        # Non-matching platform info should fail
        different_info = SnpPlatformInfo(
            smt_enabled=False, tsme_enabled=True, ecc_enabled=False,
            rapl_disabled=False, ciphertext_hiding_dram_enabled=False,
            alias_check_complete=False, tio_enabled=False
        )
        options = ValidationOptions(platform_info=different_info)
        with pytest.raises(ValueError):
            validate_report(report, chain, options)


if __name__ == '__main__':
    pytest.main([__file__]) 