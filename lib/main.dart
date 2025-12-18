import 'dart:async';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:window_manager/window_manager.dart';

// --- OUI Database (Small, Local) ---
const Map<String, String> ouiDatabase = {
  "00:00:00": "XEROX CORPORATION",
  "00:00:01": "XEROX CORPORATION",
  "00:00:02": "XEROX CORPORATION",
  // ... (rest of the local database remains here)
};


void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();
  WindowOptions windowOptions = const WindowOptions(
    size: Size(400, 700), // MODIFIED: Changed window size
    center: true,
    title: 'NetGuard LAN Scanner',
  );
  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.show();
    await windowManager.focus();
  });
  runApp(const NetGuardApp());
}

// --- Main App Widget ---
class NetGuardApp extends StatelessWidget {
  const NetGuardApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'NetGuard LAN Scanner',
      theme: ThemeData.dark().copyWith(
        primaryColor: Colors.blueGrey.shade900,
        scaffoldBackgroundColor: const Color(0xFF121212),
        appBarTheme: AppBarTheme(
          backgroundColor: Colors.blueGrey.shade900,
          elevation: 0,
        ),
        cardColor: const Color(0xFF1E1E1E),
        dialogBackgroundColor: const Color(0xFF242424),
        floatingActionButtonTheme: const FloatingActionButtonThemeData(
          backgroundColor: Colors.cyan,
        ),
        colorScheme: ColorScheme.fromSwatch(
          brightness: Brightness.dark,
          primarySwatch: Colors.cyan,
        ).copyWith(secondary: Colors.cyanAccent),
        useMaterial3: true,
      ),
      home: const LanPage(),
      debugShowCheckedModeBanner: false,
    );
  }
}

// --- Data Models ---
enum ControlStatus { uncontrolled, blocked, limited }

class DeviceControlState {
  final ControlStatus status;
  final int? limitDownKbps;
  final int? limitUpKbps;

  const DeviceControlState({
    this.status = ControlStatus.uncontrolled,
    this.limitDownKbps,
    this.limitUpKbps,
  });

  @override
  String toString() {
    if (status == ControlStatus.blocked) return 'Blocked';
    if (status == ControlStatus.limited) {
      return 'Limited (${limitDownKbps ?? 'N/A'}↓ / ${limitUpKbps ?? 'N/A'}↑ kbit)';
    }
    return 'Uncontrolled';
  }
}

class Device {
  String ip;
  final String mac;
  String hostname;
  String? customName;
  String? vendor;
  bool isSelf; // MODIFIED: To identify the user's own device
  DeviceControlState controlState;

  Device({
    required this.ip,
    required this.mac,
    required this.hostname,
    this.customName,
    this.vendor,
    this.isSelf = false, // MODIFIED: Default to false
    this.controlState = const DeviceControlState(),
  });

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Device && runtimeType == other.runtimeType && mac == other.mac;

  @override
  int get hashCode => mac.hashCode;
}


class Bandwidth {
  final double downloadBps;
  final double uploadBps;

  Bandwidth({this.downloadBps = 0.0, this.uploadBps = 0.0});
}

class NetworkInfo {
  final String gatewayIp;
  final String interfaceName;
  final String selfIp;
  final String selfMac; // MODIFIED: Added self MAC

  NetworkInfo(
      {required this.gatewayIp,
      required this.interfaceName,
      required this.selfIp,
      required this.selfMac}); // MODIFIED: Added self MAC
}

// --- LAN Page ---
class LanPage extends StatefulWidget {
  const LanPage({super.key});

  @override
  State<LanPage> createState() => _LanPageState();
}

class _LanPageState extends State<LanPage> with AutomaticKeepAliveClientMixin {
  @override
  bool get wantKeepAlive => true;

  List<Device> _devices = [];
  bool _isLoading = true;
  String? _error;
  NetworkInfo? _networkInfo;

  String? _ipCmdPath,
      _arpScanCmdPath,
      _arpSpoofCmdPath,
      _sysctlCmdPath,
      _iptablesCmdPath,
      _tcCmdPath,
      _modprobeCmdPath;

  final List<Process> _spoofingProcesses = [];
  Timer? _bandwidthTimer;
  final Map<String, Bandwidth> _bandwidthData = {};
  Map<String, int> _lastByteCounts = {};
  Map<String, String> _deviceCustomNames = {};

  bool _isSelectionMode = false;
  final Set<Device> _selectedDevices = {};

  static const String IPTABLES_POLICY_CHAIN = 'NETGUARD_POLICY';
  static const String IPTABLES_COUNT_CHAIN = 'NETGUARD_COUNT';
  static const String IPTABLES_INPUT_CHAIN = 'NETGUARD_INPUT';
  static const String IPTABLES_OUTPUT_CHAIN = 'NETGUARD_OUTPUT';
  static const String IFB_DEVICE = 'ifb0';

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(_appLifecycleObserver);
    ProcessSignal.sigint.watch().listen((_) => _handleAppExit());
    ProcessSignal.sigterm.watch().listen((_) => _handleAppExit());
    _initialize();
  }

  late final _appLifecycleObserver = AppLifecycleObserver(cleanup: _cleanup);

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(_appLifecycleObserver);
    _cleanup();
    super.dispose();
  }

  Future<void> _handleAppExit() async {
    print("Exit signal received, cleaning up...");
    await _cleanup();
    await Future.delayed(const Duration(milliseconds: 500));
    exit(0);
  }

  Future<void> _initialize() async {
    if (mounted) {
      setState(() {
        _isLoading = true;
        _error = null;
      });
    }
    try {
      await _loadDeviceNames();
      await _findCommands();
      await _checkPermissions();
      await _fetchNetworkInfo();
      await _cleanup();
      await _setupInfrastructure();
      await _scanLanNetwork();
    } catch (e, s) {
      if (mounted) setState(() => _error = 'Initialization Error:\n$e\n$s');
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }
   Future<void> _loadDeviceNames() async {
    final prefs = await SharedPreferences.getInstance();
    final keys = prefs.getKeys();
    final names = <String, String>{};
    for (String key in keys) {
      if (key.startsWith('name_')) {
        final mac = key.substring(5);
        names[mac] = prefs.getString(key)!;
      }
    }
    if (mounted) {
      setState(() {
        _deviceCustomNames = names;
      });
    }
    print("Loaded ${_deviceCustomNames.length} custom device names.");
  }

  Future<void> _saveDeviceName(String mac, String name) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('name_$mac', name);
    await _loadDeviceNames();
  }


  Future<void> _cleanup() async {
    print("--- Starting Full LAN Cleanup ---");
    _bandwidthTimer?.cancel();
    await _startStopSpoofing(start: false);
    if (_networkInfo != null) {
      await _teardownTc(_networkInfo!.interfaceName);
    }
    await _teardownIptables();
    await Process.run(
        _sysctlCmdPath ?? 'sysctl', ['-w', 'net.ipv4.ip_forward=0']);
    print("--- LAN Cleanup Complete ---");
  }

  Future<String?> _findExecutable(String name) async {
    final commonPaths = ['/usr/bin', '/usr/sbin', '/bin', '/sbin'];
    for (final path in commonPaths) {
      final file = File('$path/$name');
      if (await file.exists()) return file.path;
    }
    // Also check current user's local bin
    final home = Platform.environment['HOME'];
    if (home != null) {
      final localBin = File('$home/.local/bin/$name');
      if (await localBin.exists()) return localBin.path;
    }
    return null;
  }

  Future<void> _findCommands() async {
    final commands = {
      'ip': (path) => _ipCmdPath = path,
      'arp-scan': (path) => _arpScanCmdPath = path,
      'arpspoof': (path) => _arpSpoofCmdPath = path,
      'sysctl': (path) => _sysctlCmdPath = path,
      'iptables': (path) => _iptablesCmdPath = path,
      'tc': (path) => _tcCmdPath = path,
      'modprobe': (path) => _modprobeCmdPath = path,
    };
    final missing = <String>[];
    for (var cmd in commands.keys) {
      final path = await _findExecutable(cmd);
      if (path == null) {
        missing.add(cmd);
      } else {
        commands[cmd]!(path);
      }
    }
    if (missing.isNotEmpty) {
      throw 'Required command(s) not found: ${missing.join(', ')}.\nPlease install them (e.g., sudo apt install net-tools iproute2 dsniff arpspoof).';
    }
  }

  Future<void> _checkPermissions() async {
    if (!Platform.isLinux) throw 'This application is designed for Linux only.';
    if (Platform.environment['USER'] != 'root') {
      _error = "Traffic monitoring requires root. Please run using ./run_with_root.sh";
    }
  }

  Future<void> _fetchNetworkInfo() async {
    final routeResult =
        await Process.run(_ipCmdPath!, ['route', 'show', 'default']);
    if (routeResult.exitCode != 0) {
      throw 'Could not determine gateway IP: ${routeResult.stderr}';
    }
    final routeOutput = routeResult.stdout.toString();
    final gatewayIp =
        RegExp(r'default via ([^ ]+)').firstMatch(routeOutput)?.group(1);
    final interfaceName =
        RegExp(r'dev ([^ ]+)').firstMatch(routeOutput)?.group(1);
    if (gatewayIp == null || interfaceName == null) {
      throw 'Failed to parse gateway or interface.';
    }

    final addrResult =
        await Process.run(_ipCmdPath!, ['addr', 'show', interfaceName]);
    final addrOutput = addrResult.stdout.toString();
    final selfIp =
        RegExp(r'inet ([0-9.]+)/').firstMatch(addrOutput)?.group(1);
    final selfMac = 
        RegExp(r'link/ether (([0-9a-f]{2}:){5}[0-9a-f]{2})').firstMatch(addrOutput)?.group(1);
    
    if (selfIp == null) throw 'Failed to determine self IP address.';
    if (selfMac == null) throw 'Failed to determine self MAC address.';

    _networkInfo = NetworkInfo(
        gatewayIp: gatewayIp, interfaceName: interfaceName, selfIp: selfIp, selfMac: selfMac.toLowerCase());
  }

  Future<void> _setupInfrastructure() async {
    if (_networkInfo == null) {
      throw "Cannot setup infrastructure without network info.";
    }
    await _teardownIptables();
    await _teardownTc(_networkInfo!.interfaceName);
    await Process.run(_iptablesCmdPath!, ['-N', IPTABLES_COUNT_CHAIN]);
    await Process.run(_iptablesCmdPath!, ['-N', IPTABLES_POLICY_CHAIN]);
    await Process.run(_iptablesCmdPath!, ['-N', IPTABLES_INPUT_CHAIN]);
    await Process.run(_iptablesCmdPath!, ['-N', IPTABLES_OUTPUT_CHAIN]);
    
    await Process.run(
        _iptablesCmdPath!, ['-I', 'FORWARD', '1', '-j', IPTABLES_COUNT_CHAIN]);
    await Process.run(
        _iptablesCmdPath!, ['-I', 'FORWARD', '2', '-j', IPTABLES_POLICY_CHAIN]);
    await Process.run(
        _iptablesCmdPath!, ['-I', 'INPUT', '1', '-j', IPTABLES_INPUT_CHAIN]);
    await Process.run(
        _iptablesCmdPath!, ['-I', 'OUTPUT', '1', '-j', IPTABLES_OUTPUT_CHAIN]);
    await _setupTc(_networkInfo!.interfaceName);
  }

  Future<void> _teardownIptables() async {
    await Process.run(
            _iptablesCmdPath!, ['-D', 'FORWARD', '-j', IPTABLES_POLICY_CHAIN])
        .catchError((_) {});
    await Process.run(
            _iptablesCmdPath!, ['-D', 'FORWARD', '-j', IPTABLES_COUNT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_POLICY_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-X', IPTABLES_POLICY_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_COUNT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-X', IPTABLES_COUNT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_INPUT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-X', IPTABLES_INPUT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_OUTPUT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-X', IPTABLES_OUTPUT_CHAIN])
        .catchError((_) {});
    
    // Clean up references in main chains
    await Process.run(_iptablesCmdPath!, ['-D', 'FORWARD', '-j', IPTABLES_COUNT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-D', 'FORWARD', '-j', IPTABLES_POLICY_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-D', 'INPUT', '-j', IPTABLES_INPUT_CHAIN])
        .catchError((_) {});
    await Process.run(_iptablesCmdPath!, ['-D', 'OUTPUT', '-j', IPTABLES_OUTPUT_CHAIN])
        .catchError((_) {});
  }
  
  String? _getVendor(String mac) {
    if (mac.length < 8) return null;
    final oui = mac.substring(0, 8).toUpperCase();
    return ouiDatabase[oui];
  }

  Future<void> _scanLanNetwork() async {
    if (_networkInfo == null) throw 'Network Info not available for LAN scan.';
    await _startStopSpoofing(start: false);
    if (!mounted) return;
    setState(() {
      _isLoading = true;
       if (!(_error?.startsWith("Warning") ?? false)) {
        _error = null;
      }
    });
    try {
      final result = await Process.run(_arpScanCmdPath!,
          ['--interface=${_networkInfo!.interfaceName}', '--localnet', '--ignoredups']);
      if (result.exitCode != 0) throw 'LAN Scan failed: ${result.stderr}';
      
      final lines = result.stdout.toString().split('\n');
      final newDevices = <Device>[];
      final regex = RegExp(r'^([0-9.]+)\s+([0-9a-fA-F:]+)\s+(.*)');

      // MODIFIED: Add "My PC" device first
      final selfDevice = Device(
        ip: _networkInfo!.selfIp,
        mac: _networkInfo!.selfMac,
        hostname: '(My PC)',
        vendor: _getVendor(_networkInfo!.selfMac),
        isSelf: true,
        customName: "My PC"
      );
      newDevices.add(selfDevice);

      for (var line in lines) {
        final match = regex.firstMatch(line);
        if (match != null) {
          final ip = match.group(1)!;
          final mac = match.group(2)!.toLowerCase();
          // Exclude gateway and self IP from the scan results to avoid duplication
          if (ip != _networkInfo!.gatewayIp && ip != _networkInfo!.selfIp) {
            final existingDevice = _devices.firstWhere((d) => d.mac == mac,
                orElse: () =>
                    Device(ip: ip, mac: mac, hostname: match.group(3)!));
            
            existingDevice.ip = ip;
            existingDevice.hostname = match.group(3)!;
            existingDevice.customName = _deviceCustomNames[mac];
            existingDevice.vendor = _getVendor(mac);
            
            newDevices.add(existingDevice);
          }
        }
      }
      if (!mounted) return;
      setState(() {
        _devices = newDevices;
        // Sort to keep "My PC" at the top
        _devices.sort((a, b) {
          if (a.isSelf) return -1;
          if (b.isSelf) return 1;
          return a.ip.compareTo(b.ip);
        });
        if (_devices.length <= 1) { // Only "My PC" is found
          _error = "Scan complete. No other devices found on LAN.";
        }
      });
      await _updateIptablesRules();
      await _applyTcRules();
      await _startStopSpoofing(start: true);
      _startBandwidthMonitoring();
    } catch (e, s) {
      if (mounted) setState(() => _error = 'LAN Scan Error:\n$e\n$s');
    } finally {
      if (mounted) setState(() => _isLoading = false);
    }
  }

  Future<void> _startStopSpoofing({required bool start}) async {
    if (_networkInfo == null || Platform.environment['USER'] != 'root') return;
    
    // Don't spoof our own device
    final targets = _devices.where((d) => !d.isSelf).toList();
    if (targets.isEmpty) return;

    if (start) {
      print("Starting ARP spoofing...");
      await Process.run(_sysctlCmdPath!, ['-w', 'net.ipv4.ip_forward=1']);
      if (_spoofingProcesses.isNotEmpty) return;
      for (final device in targets) {
        final p1 = await Process.start(_arpSpoofCmdPath!,
            ['-i', _networkInfo!.interfaceName, '-t', device.ip, _networkInfo!.gatewayIp]);
        final p2 = await Process.start(_arpSpoofCmdPath!,
            ['-i', _networkInfo!.interfaceName, '-t', _networkInfo!.gatewayIp, device.ip]);
        _spoofingProcesses.addAll([p1, p2]);
      }
    } else {
      print("Stopping all spoofing processes...");
      for (var process in _spoofingProcesses) {
        process.kill(ProcessSignal.sigint);
      }
      _spoofingProcesses.clear();
    }
  }

  Future<void> _updateIptablesRules() async {
    if (_networkInfo == null || Platform.environment['USER'] != 'root') return;

    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_COUNT_CHAIN]);
    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_INPUT_CHAIN]);
    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_OUTPUT_CHAIN]);
    
    for (final device in _devices) {
      if (device.isSelf) {
         // Current device traffic (My PC)
        await Process.run(
            _iptablesCmdPath!, ['-A', IPTABLES_INPUT_CHAIN, '-d', device.ip]);
        await Process.run(
            _iptablesCmdPath!, ['-A', IPTABLES_OUTPUT_CHAIN, '-s', device.ip]);
      } else {
        // Forwarded traffic (Other devices)
        await Process.run(
            _iptablesCmdPath!, ['-A', IPTABLES_COUNT_CHAIN, '-s', device.ip]);
        await Process.run(
            _iptablesCmdPath!, ['-A', IPTABLES_COUNT_CHAIN, '-d', device.ip]);
      }
    }

    await Process.run(_iptablesCmdPath!, ['-F', IPTABLES_POLICY_CHAIN]);
    for (final device in _devices.where((d) => !d.isSelf)) {
      if (device.controlState.status == ControlStatus.blocked) {
        await Process.run(_iptablesCmdPath!,
            ['-A', IPTABLES_POLICY_CHAIN, '-s', device.ip, '-j', 'DROP']);
        await Process.run(_iptablesCmdPath!,
            ['-A', IPTABLES_POLICY_CHAIN, '-d', device.ip, '-j', 'DROP']);
      }
    }
    await Process.run(
        _iptablesCmdPath!, ['-A', IPTABLES_POLICY_CHAIN, '-j', 'ACCEPT']);
  }

  Future<void> _setupTc(String interface) async {
     if (Platform.environment['USER'] != 'root') return;
    print("Setting up TC infrastructure...");
    await _modprobeCmdPath!.run(['ifb', 'numifbs=1']);
    await _ipCmdPath!.run(['link', 'set', IFB_DEVICE, 'up']);
    await _tcCmdPath!
        .run(['qdisc', 'add', 'dev', interface, 'handle', 'ffff:', 'ingress']);
    await _tcCmdPath!.run([
      'filter',
      'add',
      'dev',
      interface,
      'parent',
      'ffff:',
      'protocol',
      'ip',
      'u32',
      'match',
      'u32',
      '0',
      '0',
      'action',
      'mirred',
      'egress',
      'redirect',
      'dev',
      IFB_DEVICE
    ]);
  }

  Future<void> _teardownTc(String interface) async {
     if (Platform.environment['USER'] != 'root') return;
    print("Tearing down TC infrastructure...");
    await _tcCmdPath!
        .run(['qdisc', 'del', 'dev', interface, 'ingress']).catchError((_) {});
    await _tcCmdPath!
        .run(['qdisc', 'del', 'dev', interface, 'root']).catchError((_) {});
    await _tcCmdPath!
        .run(['qdisc', 'del', 'dev', IFB_DEVICE, 'root']).catchError((_) {});
    await _ipCmdPath!
        .run(['link', 'set', IFB_DEVICE, 'down']).catchError((_) {});
  }

  Future<void> _applyDeviceControl(Device device) async {
    await _updateIptablesRules();
    await _applyTcRules();
    if (mounted) setState(() {});
  }

  Future<void> _applyTcRules() async {
    if (_networkInfo == null || Platform.environment['USER'] != 'root') return;
    final interface = _networkInfo!.interfaceName;
    print("Applying new TC rules...");

    await _tcCmdPath!
        .run(['qdisc', 'del', 'dev', interface, 'root']).catchError((_) {});
    await _tcCmdPath!
        .run(['qdisc', 'del', 'dev', IFB_DEVICE, 'root']).catchError((_) {});

    await _tcCmdPath!.run([
      'qdisc',
      'add',
      'dev',
      interface,
      'root',
      'handle',
      '1:',
      'htb',
      'default',
      '9999'
    ]);
    await _tcCmdPath!.run([
      'qdisc',
      'add',
      'dev',
      IFB_DEVICE,
      'root',
      'handle',
      '2:',
      'htb',
      'default',
      '9999'
    ]);

    for (final device in _devices.where((d) => !d.isSelf)) {
      if (device.controlState.status == ControlStatus.limited) {
        final state = device.controlState;
        final classId =
            (int.tryParse(device.mac.split(':').last, radix: 16) ?? 1) % 4094 +
                1;

        if (state.limitUpKbps != null && state.limitUpKbps! > 0) {
          await _tcCmdPath!.run([
            'class',
            'add',
            'dev',
            interface,
            'parent',
            '1:',
            'classid',
            '1:$classId',
            'htb',
            'rate',
            '${state.limitUpKbps}kbit'
          ]);
          await _tcCmdPath!.run([
            'filter',
            'add',
            'dev',
            interface,
            'parent',
            '1:',
            'protocol',
            'ip',
            'prio',
            '1',
            'u32',
            'match',
            'ip',
            'src',
            device.ip,
            'flowid',
            '1:$classId'
          ]);
        }

        if (state.limitDownKbps != null && state.limitDownKbps! > 0) {
          await _tcCmdPath!.run([
            'class',
            'add',
            'dev',
            IFB_DEVICE,
            'parent',
            '2:',
            'classid',
            '2:$classId',
            'htb',
            'rate',
            '${state.limitDownKbps}kbit'
          ]);
          await _tcCmdPath!.run([
            'filter',
            'add',
            'dev',
            IFB_DEVICE,
            'parent',
            '2:',
            'protocol',
            'ip',
            'prio',
            '1',
            'u32',
            'match',
            'ip',
            'dst',
            device.ip,
            'flowid',
            '2:$classId'
          ]);
        }
      }
    }
  }

  void _startBandwidthMonitoring() {
    _bandwidthTimer?.cancel();
    _lastByteCounts.clear();
     if (Platform.environment['USER'] != 'root') return;
    _bandwidthTimer =
        Timer.periodic(const Duration(seconds: 2), (_) => _updateBandwidth());
  }

  Future<void> _updateBandwidth() async {
    if (!mounted || _iptablesCmdPath == null) return;

    // Parse all chains
    var stdout = "";
    
    // Read FORWARD chain (other devices)
    var result = await Process.run(
        _iptablesCmdPath!, ['-L', IPTABLES_COUNT_CHAIN, '-n', '-v', '-x']);
    if (result.exitCode == 0) stdout += result.stdout.toString();
    
    // Read INPUT chain (My PC download)
    result = await Process.run(
        _iptablesCmdPath!, ['-L', IPTABLES_INPUT_CHAIN, '-n', '-v', '-x']);
    if (result.exitCode == 0) stdout += result.stdout.toString();

    // Read OUTPUT chain (My PC upload)
    result = await Process.run(
        _iptablesCmdPath!, ['-L', IPTABLES_OUTPUT_CHAIN, '-n', '-v', '-x']);
    if (result.exitCode == 0) stdout += result.stdout.toString();

    final lines = stdout.split('\n');
    final newByteCounts = <String, int>{};
    final ipToMac = {for (var d in _devices) d.ip: d.mac};

    for (var line in lines) {
      final parts = line.trim().split(RegExp(r'\s+'));

      if (parts.length < 8) continue;

      final bytes = int.tryParse(parts[1]) ?? 0;
      final source = parts[6];
      final destination = parts[7];

      final macSource = ipToMac[source];
      final macDest = ipToMac[destination];

      if (macSource != null) {
        newByteCounts['$macSource-upload'] =
            (newByteCounts['$macSource-upload'] ?? 0) + bytes;
      }
      if (macDest != null) {
        newByteCounts['$macDest-download'] =
            (newByteCounts['$macDest-download'] ?? 0) + bytes;
      }
    }

    final newBandwidthData = <String, Bandwidth>{};
    for (final device in _devices) {
      final uploadKey = '${device.mac}-upload';
      final downloadKey = '${device.mac}-download';

      final currentUploadBytes = newByteCounts[uploadKey] ?? 0;
      final currentDownloadBytes = newByteCounts[downloadKey] ?? 0;

      final lastUploadBytes = _lastByteCounts[uploadKey] ?? 0;
      final lastDownloadBytes = _lastByteCounts[downloadKey] ?? 0;

      final uploadBps = ((currentUploadBytes - lastUploadBytes) * 8) / 2.0;
      final downloadBps = ((currentDownloadBytes - lastDownloadBytes) * 8) / 2.0;

      newBandwidthData[device.mac] = Bandwidth(
        uploadBps: uploadBps >= 0 ? uploadBps : 0,
        downloadBps: downloadBps >= 0 ? downloadBps : 0,
      );
    }

    if (mounted) {
      setState(() {
        _bandwidthData.clear();
        _bandwidthData.addAll(newBandwidthData);
      });
      _lastByteCounts = newByteCounts;
    }
  }

  @override
  Widget build(BuildContext context) {
    super.build(context);
    return Scaffold(
      appBar: _isSelectionMode
          ? _buildSelectionAppBar()
          : AppBar(title: const Text('LAN Devices')),
      body: _buildBody(),
      floatingActionButton: _isSelectionMode
          ? null
          : FloatingActionButton(
              onPressed: _isLoading ? null : _scanLanNetwork,
              tooltip: 'Scan LAN',
              child: _isLoading
                  ? const CircularProgressIndicator(color: Colors.white)
                  : const Icon(Icons.refresh),
            ),
    );
  }

  AppBar _buildSelectionAppBar() {
    return AppBar(
      backgroundColor: Colors.indigo.shade800,
      leading: IconButton(
        icon: const Icon(Icons.close),
        onPressed: () => setState(() {
          _isSelectionMode = false;
          _selectedDevices.clear();
        }),
      ),
      title: Text('${_selectedDevices.length} selected'),
      actions: [
        IconButton(
            icon: const Icon(Icons.block),
            tooltip: 'Block Selected',
            onPressed: () => _applyBulkAction(ControlStatus.blocked)),
        IconButton(
            icon: const Icon(Icons.wifi_off),
            tooltip: 'Uncontrol Selected',
            onPressed: () => _applyBulkAction(ControlStatus.uncontrolled)),
      ],
    );
  }

  void _applyBulkAction(ControlStatus status) {
     if (Platform.environment['USER'] != 'root') {
      _showErrorDialog("Root permissions are required to control devices.");
      return;
    }
    for (final device in _selectedDevices) {
       if (device.isSelf) continue;
      device.controlState = DeviceControlState(status: status);
    }
    if (_selectedDevices.isNotEmpty) _applyDeviceControl(_selectedDevices.first);

    setState(() {
      _isSelectionMode = false;
      _selectedDevices.clear();
    });
  }

  Widget _buildBody() {
    if (_isLoading && _devices.isEmpty) {
      return const Center(child: CircularProgressIndicator());
    }
    if (_error != null && _devices.length <=1) {
      return Center(
          child: Padding(
              padding: const EdgeInsets.all(16.0),
              child: Text(_error!,
                  style: const TextStyle(color: Colors.orangeAccent),
                  textAlign: TextAlign.center)));
    }
    if (_devices.isEmpty) {
      return const Center(
          child: Text('Press the scan button to find devices on your LAN.'));
    }

    return RefreshIndicator(
      onRefresh: _scanLanNetwork,
      child: ListView.builder(
        itemCount: _devices.length,
        itemBuilder: (context, index) {
          final device = _devices[index];
          final bandwidth = _bandwidthData[device.mac] ?? Bandwidth();
          final isSelected = _selectedDevices.contains(device);
          return DeviceTile(
            device: device,
            bandwidth: bandwidth,
            isSelected: isSelected,
            isSelectionMode: _isSelectionMode,
            onTap: () {
              if (device.isSelf) return; // Don't allow selecting "My PC"
              if (_isSelectionMode) {
                setState(() {
                  if (isSelected) {
                    _selectedDevices.remove(device);
                  } else {
                    _selectedDevices.add(device);
                  }
                  if (_selectedDevices.isEmpty) _isSelectionMode = false;
                });
              } else {
                _showControlDialog(device);
              }
            },
            onLongPress: () {
              if (device.isSelf) return; // Don't allow selection mode for "My PC"
              if (!_isSelectionMode) {
                setState(() {
                  _isSelectionMode = true;
                  _selectedDevices.add(device);
                });
              }
            },
            onEditName: () => _showEditNameDialog(device),
          );
        },
      ),
    );
  }

   void _showEditNameDialog(Device device) async {
    final nameController =
        TextEditingController(text: device.customName ?? "");
    final newName = await showDialog<String>(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Edit Device Name'),
        content: TextField(
          controller: nameController,
          autofocus: true,
          decoration: const InputDecoration(hintText: 'Enter custom name'),
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.of(context).pop(),
              child: const Text('Cancel')),
          FilledButton(
            onPressed: () {
              Navigator.of(context).pop(nameController.text);
            },
            child: const Text('Save'),
          ),
        ],
      ),
    );
    if (newName != null && newName.isNotEmpty) {
      await _saveDeviceName(device.mac, newName);
      if (mounted) {
        setState(() {
          final deviceInList = _devices.firstWhere((d) => d.mac == device.mac);
          deviceInList.customName = newName;
        });
      }
    }
  }


  void _showControlDialog(Device device) async {
    if (Platform.environment['USER'] != 'root') {
      _showErrorDialog("Root permissions are required to control devices.");
      return;
    }
    final newControlState = await showDialog<DeviceControlState>(
      context: context,
      builder: (context) =>
          DeviceControlDialog(initialState: device.controlState),
    );
    if (newControlState != null) {
      setState(() {
        device.controlState = newControlState;
      });
      await _applyDeviceControl(device);
    }
  }
  
  void _showErrorDialog(String message) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: const Text('Permission Error'),
        content: Text(message),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('OK'),
          ),
        ],
      ),
    );
  }
}

// --- UI WIDGETS ---
class AppLifecycleObserver extends WidgetsBindingObserver {
  final Future<void> Function() cleanup;
  AppLifecycleObserver({required this.cleanup});

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    if (state == AppLifecycleState.detached) {
      cleanup();
    }
  }
}

class DeviceTile extends StatelessWidget {
  final Device device;
  final Bandwidth bandwidth;
  final bool isSelected;
  final bool isSelectionMode;
  final VoidCallback onTap;
  final VoidCallback onLongPress;
  final VoidCallback onEditName;

  const DeviceTile({
    super.key,
    required this.device,
    required this.bandwidth,
    required this.isSelected,
    required this.isSelectionMode,
    required this.onTap,
    required this.onLongPress,
    required this.onEditName,
  });

  String _formatSpeed(double bps) {
    if (bps < 1000) return '${bps.toStringAsFixed(0)} bps';
    if (bps < 1000 * 1000) return '${(bps / 1000).toStringAsFixed(1)} kbps';
    return '${(bps / (1000 * 1000)).toStringAsFixed(1)} Mbps';
  }

  IconData get leadingIcon {
    if (device.isSelf) return Icons.computer;
    switch (device.controlState.status) {
      case ControlStatus.blocked:
        return Icons.lock;
      case ControlStatus.limited:
        return Icons.speed;
      case ControlStatus.uncontrolled:
        return Icons.wifi;
    }
  }

  Color get leadingIconColor {
     if (device.isSelf) return Colors.lightBlueAccent;
    switch (device.controlState.status) {
      case ControlStatus.blocked:
        return Colors.redAccent;
      case ControlStatus.limited:
        return Colors.amberAccent;
      case ControlStatus.uncontrolled:
        return Colors.greenAccent;
    }
  }

  @override
  Widget build(BuildContext context) {
    String primaryDisplayName;
    String? secondaryDisplayName;

    if (device.customName != null && device.customName!.isNotEmpty) {
      primaryDisplayName = device.customName!;
      secondaryDisplayName = device.vendor ?? device.hostname;
      if (secondaryDisplayName == primaryDisplayName) secondaryDisplayName = device.hostname;
    } else {
      primaryDisplayName = device.vendor ?? device.hostname;
      secondaryDisplayName = (device.vendor != null && device.hostname != '(unknown)') ? device.hostname : null;
    }
    if (primaryDisplayName == '(unknown)' && device.vendor != null) primaryDisplayName = device.vendor!;


    return Card(
      margin: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
      color: isSelected
          ? Colors.blue.withOpacity(0.3)
          : (device.isSelf ? Colors.blueGrey.shade800.withOpacity(0.5) : Theme.of(context).cardColor),
      child: ListTile(
        onTap: onTap,
        onLongPress: onLongPress,
        leading: Icon(leadingIcon, color: leadingIconColor),
        title: Text(primaryDisplayName,
            style: const TextStyle(fontWeight: FontWeight.bold)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            if (secondaryDisplayName != null && secondaryDisplayName.isNotEmpty)
              Text(secondaryDisplayName, style: TextStyle(color: Colors.grey.shade400, fontSize: 12)),
            Text('IP: ${device.ip}\nMAC: ${device.mac}'),
            const SizedBox(height: 4),
            Row(
              children: [
                const Icon(Icons.download_outlined,
                    size: 14, color: Colors.cyanAccent),
                Text(' ${_formatSpeed(bandwidth.downloadBps)}',
                    style: const TextStyle(color: Colors.cyanAccent)),
                const SizedBox(width: 12),
                const Icon(Icons.upload_outlined,
                    size: 14, color: Colors.orangeAccent),
                Text(' ${_formatSpeed(bandwidth.uploadBps)}',
                    style: const TextStyle(color: Colors.orangeAccent)),
              ],
            ),
          ],
        ),
        trailing: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            if (isSelectionMode && !device.isSelf)
              Checkbox(value: isSelected, onChanged: (v) => onTap())
            else if (!device.isSelf)
              IconButton(
                icon: const Icon(Icons.edit, size: 20, color: Colors.grey),
                onPressed: onEditName,
                tooltip: 'Edit Name',
              ),
          ],
        ),
      ),
    );
  }
}

class DeviceControlDialog extends StatefulWidget {
  final DeviceControlState initialState;
  const DeviceControlDialog({super.key, required this.initialState});

  @override
  State<DeviceControlDialog> createState() => _DeviceControlDialogState();
}

class _DeviceControlDialogState extends State<DeviceControlDialog> {
  late ControlStatus _status;
  late TextEditingController _downController;
  late TextEditingController _upController;
  final _formKey = GlobalKey<FormState>();

  @override
  void initState() {
    super.initState();
    _status = widget.initialState.status;
    _downController = TextEditingController(
        text: widget.initialState.limitDownKbps?.toString() ?? '64');
    _upController = TextEditingController(
        text: widget.initialState.limitUpKbps?.toString() ?? '64');
  }

  @override
  void dispose() {
    _downController.dispose();
    _upController.dispose();
    super.dispose();
  }

  void _adjustSpeed(TextEditingController controller, int amount) {
    final currentValue = int.tryParse(controller.text) ?? 0;
    final newValue = currentValue + amount;
    controller.text = (newValue > 1 ? newValue : 1).toString();
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('Set Device Control'),
      content: Form(
        key: _formKey,
        child: SingleChildScrollView(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              RadioListTile<ControlStatus>(
                title: const Text('Uncontrolled'),
                value: ControlStatus.uncontrolled,
                groupValue: _status,
                onChanged: (v) => setState(() => _status = v!),
              ),
              RadioListTile<ControlStatus>(
                title: const Text('Blocked'),
                value: ControlStatus.blocked,
                groupValue: _status,
                onChanged: (v) => setState(() => _status = v!),
              ),
              RadioListTile<ControlStatus>(
                title: const Text('Speed Limit (kbit/s)'),
                value: ControlStatus.limited,
                groupValue: _status,
                onChanged: (v) => setState(() => _status = v!),
              ),
              if (_status == ControlStatus.limited)
                Padding(
                  padding: const EdgeInsets.symmetric(
                      horizontal: 8.0, vertical: 8.0),
                  child: Column(
                    children: [
                      _buildSpeedControl('Download', _downController),
                      const SizedBox(height: 16),
                      _buildSpeedControl('Upload', _upController),
                    ],
                  ),
                ),
            ],
          ),
        ),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Cancel')),
        FilledButton(onPressed: _submit, child: const Text('Apply')),
      ],
    );
  }

  Widget _buildSpeedControl(String label, TextEditingController controller) {
    return Row(
      children: [
        IconButton(
          icon: const Icon(Icons.remove),
          onPressed: () => _adjustSpeed(controller, -16),
        ),
        Expanded(
          child: TextFormField(
            controller: controller,
            textAlign: TextAlign.center,
            decoration: InputDecoration(
              labelText: label,
              prefixIcon:
                  Icon(label == 'Download' ? Icons.download : Icons.upload),
            ),
            keyboardType: TextInputType.number,
            inputFormatters: [FilteringTextInputFormatter.digitsOnly],
            validator: (v) =>
                (v == null || v.isEmpty || int.tryParse(v)! <= 0)
                    ? 'Invalid'
                    : null,
          ),
        ),
        IconButton(
          icon: const Icon(Icons.add),
          onPressed: () => _adjustSpeed(controller, 16),
        ),
      ],
    );
  }

  void _submit() {
    if (_status == ControlStatus.limited) {
      if (!_formKey.currentState!.validate()) {
        return;
      }
    }

    final newState = DeviceControlState(
      status: _status,
      limitDownKbps: _status == ControlStatus.limited
          ? int.tryParse(_downController.text)
          : null,
      limitUpKbps: _status == ControlStatus.limited
          ? int.tryParse(_upController.text)
          : null,
    );
    Navigator.of(context).pop(newState);
  }
}

extension on String {
  Future<ProcessResult> run(List<String> args) => Process.run(this, args);
}
