"""
HexStrike AI - Core Infrastructure Package
"""

from src.core.visual import ModernVisualEngine, ColoredFormatter, setup_logging, BANNER
from src.core.cache import HexStrikeCache, AdvancedCache, TelemetryCollector, cache, telemetry
from src.core.error_handler import (
    ErrorType,
    RecoveryAction,
    ErrorContext,
    RecoveryStrategy,
    IntelligentErrorHandler,
    GracefulDegradation,
    FailureRecoverySystem,
    error_handler,
    degradation_manager,
    failure_recovery,
)
from src.core.process_manager import (
    active_processes,
    process_lock,
    ProcessManager,
    ProcessPool,
    ResourceMonitor,
    PerformanceDashboard,
    EnhancedProcessManager,
    enhanced_process_manager,
)
from src.core.files import (
    PythonEnvironmentManager,
    FileOperationsManager,
    env_manager,
    file_manager,
)
from src.core.executor import (
    EnhancedCommandExecutor,
    execute_command,
    execute_command_with_recovery,
    _rebuild_command_with_params,
    _determine_operation_type,
    execute_nmap_scan,
    execute_gobuster_scan,
    execute_nuclei_scan,
    execute_nikto_scan,
    execute_sqlmap_scan,
    execute_ffuf_scan,
    execute_feroxbuster_scan,
    execute_katana_scan,
    execute_httpx_scan,
    execute_wpscan_scan,
    execute_dirsearch_scan,
    execute_arjun_scan,
    execute_paramspider_scan,
    execute_dalfox_scan,
    execute_amass_scan,
    execute_subfinder_scan,
)
from src.core.domain_utils import (
    normalize_targets,
    extract_domain,
    ensure_url,
    extract_multi_target_info,
    wrap_endpoint_for_multi_target,
    MultiTargetAPIRouter,
)
