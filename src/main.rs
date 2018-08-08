extern crate num_cpus;
extern crate config;
extern crate dbus;
extern crate docopt;
extern crate glob;
extern crate nix;
extern crate bytebuffer;
extern crate mio;
extern crate memmap;
extern crate psutil;

use std::thread;
use std::collections::HashMap;
use std::fs::File;
use std::io::prelude::{Read, Write};
use std::{rc, cell};
use config::*;
use docopt::Docopt;
use glob::glob;
use nix::unistd::geteuid;
use nix::sys::signal;
use dbus::{Connection,Message,BusType};

const USAGE: &'static str = "
Lenovo CPU Throttling Daemon for linux

Usage:
    lenovo-throttled (-h|--help)
    lenovo-throttled --version
    lenovo-throttled
    
Options:
    -h --help               Show this screen.
    --version               Show version.
    --config <configfile>  Config file path [Default: /etc/lenovo-throttled.toml]
";

const VOLTAGE_PLANES: &'static [(&'static str, u32); 5] = &[
    ("CORE", 0),
    ("GPU", 1),
    ("CACHE", 2),
    ("UNCORE", 3),
    ("ANALOGIO", 4)
];

const TRIP_TEMP_RANGE: (u32, u32) = (40, 97);
const C_TDP_RANGE: (u64,u64) = (0, 2);

fn main() {
    let args = Docopt::new(USAGE)
                        .and_then(|dopt| dopt.parse())
                        .unwrap_or_else(|e| e.exit());
    let arg_config = String::from(args.get_str("--config"));
    let settings = load_config(arg_config);
    let debug = settings.get_bool("General.debug").unwrap();

    if !geteuid().is_root() {
        panic!("[E] This must be run as root");
    }

    //TODO: A global to store power state
    let mut power = HashMap::new();
    power["source"] = "";
    power["method"] = "polling";

    *power.entry("source").or_insert("") = if is_on_ac(settings) {
        "AC"
    } else {
        "BATTERY"
    };

    let mut regs = calc_reg_values(settings);
    
    if !settings.get_bool("General.Enabled").unwrap() {
        panic!("[E] Daemon Disabled in Config");
    }

    let mut event_poller = mio::Poll::new().unwrap();
    let events = mio::Events::with_capacity(100);

    let th_builder = thread::Builder::new().name("power_thread".into());
    let th_handler = th_builder.spawn(move || power_thread(settings, regs, exit_event, power)).unwrap();
    
    undervolt(settings);
    
    // handle dbus events for applying undervolt on resume from sleep/hybernate
    fn handle_sleep_callback(sleeping: bool, settings: Config) {
        if !sleeping {
            undervolt(settings);
        }
    }

    let done: rc::Rc<cell::Cell<bool>> = Default::default();
    let done2 = done.clone();
    
    fn handle_ac_callback(message: std::result::Result<&dbus::Message, dbus::Error>, power: HashMap<&str,&str>, debug: bool ) {   
        let v: Vec<&str> = message.unwrap().read1().unwrap();
        if debug { println!("The names on the D-Bus are: {:?}", v); }
        if v[1] == "0" {
            *power.get_mut("source").unwrap() = "BATTERY";
            *power.get_mut("method").unwrap() = "dbus";
        } else {
            *power.get_mut("source").unwrap() = "AC";
            *power.get_mut("method").unwrap() = "polling";
        }
       
    }

    let bus = match Connection::get_private(BusType::System) { 
        Ok(f) => f,
        Err(status) => panic!("[E] Cannot connect to dbus: {}",status)
    };

    // add dbus receiver only if undervolt is enabled in config
    if VOLTAGE_PLANES.iter().any(|plane| settings.get_float(format!("UNDERVOLT.{}", plane.0).as_str()).unwrap() != 0.0) {
        let message = Message::new_method_call("org.freedesktop.login1", "", "org.freedesktop.login1.Manager", "PrepareForSleep").unwrap();
        bus.add_handler(bus.send_with_reply(message,move |reply| { 
            handle_ac_callback(reply,power,debug);
            done2.set(true);
            }).unwrap());
    }
    
    let acmessage = Message::new_method_call("", "/org/freedesktop/UPower/devices/line_power_AC", "org.freedesktop.DBus.Properties", "PropertiesChanged").unwrap();
    bus.add_handler(bus.send_with_reply(acmessage,move |reply| {
        handle_ac_callback(reply, power, debug);
        done2.set(true);
         }).unwrap());

    extern fn handle_loop_exit(i: nix::libc::c_int) {
        println!("Got {}: Shutting Down..",i);
        exit_event.set(true);
    };

    let handler = signal::SigHandler::Handler(handle_loop_exit);
    let sig_action = signal::SigAction::new(handler,signal::SaFlags::SA_RESTART,signal::SigSet::empty());
    signal::sigaction(signal::SIGINT, &sig_action);
    signal::sigaction(signal::SIGTERM, &sig_action);
    
    while !done.get() {
        bus.incoming(200).next();
    }

    loop {
        event_poller.poll(&mut events, None).unwrap();

        for event in events.iter() {
            match event.token() {
                EXIT => {
                    break;
                },
                _ => unreachable!(),
            }
        }
    }
    //On exit from loop do
    exit_event.set();
    event_loop.close();
    th_handler.join();
}

fn writemsr(msr: i64, val: u64) {
    
    let msr_list = match glob::glob("/dev/cpu/*/msr") {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}, You must load kernel msr module", e)
    };

    for addr in msr_list {
        let f = nix::fcntl::open(&addr.unwrap().to_str(),
            nix::fcntl::OFlag::O_WRONLY,
            nix::sys::stat::Mode::empty()
            );
        match f {
            Ok(f) => {    
            nix::unistd::lseek(f, msr, nix::unistd::Whence::SeekSet);
            let buf = bytebuffer::ByteBuffer::new();
            buf.write_u64(val);
            let mut result = [0;8];
            buf.write(&mut result);
            nix::unistd::write(f, &result).expect("Couldn't Write Buffer to msr");
            nix::unistd::close(f);
            },
            Err(e) => panic!("[E] Unable to write to MSR")
        }
    }
}

// returns the value between from_bit and to_bit as unsigned long
fn readmsr(msr: i64, from_bit: u32, to_bit: u32) -> Vec<u64> {
    /*
    from_bit.unwrap_or(0);
    to_bit.unwrap_or(63);
    cpu.unwrap_or(-1);
    flatten.unwrap_or(false);
    */
    
    // assert!(cpu == -1 || cpu <= num_cpus::get() as i32);
    
    if from_bit < to_bit {
        panic!("[E] Wrong readmsr bit params");
    };

    let msr_list = match glob::glob("/dev/cpu/*/msr") {
        Ok(f) => f,
        Err(e) => panic!("Error: {:?}, You must load kernel msr module", e)
    };
    
    let mut output = Vec::new();
    for addr in msr_list {
        let f = nix::fcntl::open(&addr.unwrap().to_str(),
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty()
            ).expect("Unable to read from MSR");
        nix::unistd::lseek(f, msr, nix::unistd::Whence::SeekSet);
        let mut val = [0;8];
        nix::unistd::read(f, &mut val);
        let unpack = bytebuffer::ByteBuffer::from_bytes(&val);
        nix::unistd::close(f);
        //Does this work?
        let mut mask : u64 = 0;
        for x in from_bit..to_bit+1 {
            mask += 2u64.pow(x);
        }
        output.push((unpack.read_u64() & mask) >> from_bit);
    }
    return output;
}

fn is_on_ac(settings: Config) -> bool {
    let path = settings.get_str("sysfs_power_path").unwrap();
    let mut file = match File::open(path) {
        Ok(f) => f, 
        Err(why) => panic!("couldn't open {}", path)
    };

    let mut s = String::new();
    file.read_to_string(&mut s);

    //maybe just bool::from_str(s).unwrap();
    match s.as_str() {
        "0" => false,
        "1" => true
    }
}

fn undervolt(config: Config) {
    let debug = config.get_bool("General.debug").unwrap();
    for plane in VOLTAGE_PLANES.iter() {
        let mut write_value = calc_undervolt_msr(plane, config.get_float(format!("UNDERVOLT.{}", plane.0).as_str()).unwrap());
        writemsr(0x150, write_value);
        if debug {
            write_value &= 0xFFFFFFFF;
            writemsr(0x150, 0x8000001000000000 | ( plane.1 as u64 )<< 40);
            //Porting Notes: Flatten was true, cpu = none
            let read_value = readmsr(0x150, 0, 63);
            let match_check = write_value == read_value[0];
            
            println!("[D] Undervolt plane {:?} - write {:?} - read {:?} - match {}",
                plane, write_value, read_value, match_check);
        }
    }
}


fn calc_undervolt_msr(plane: &(&str,u32), offset:f64) -> u64 {
    assert!(offset <= 0.0);
    assert!(VOLTAGE_PLANES.contains(plane));
    let mut offset = (offset * 1.024).round() as u64;
    offset = 0xFFE00000 & ((offset & 0xFFF) << 21);
    return 0x8000001100000000 | ((plane.1 as u64) << 40) | offset
}

fn load_config(config_path: String) -> Config {
    let mut settings = Config::default();
    settings.merge(config::File::with_name(config_path.as_str())).unwrap();
    settings.set_default("debug", false).unwrap();
    settings.set_default("sysfs_power_path", "/sys/class/power_supply/AC/online").unwrap();
    settings.set_default("trip_temp_range.low", TRIP_TEMP_RANGE.0.to_string() ).unwrap();
    settings.set_default("trip_temp_range.hi", TRIP_TEMP_RANGE.1.to_string() ).unwrap();
    settings.set_default("c_tdp_range.lo", C_TDP_RANGE.0.to_string() ).unwrap();
    settings.set_default("c_tdp_range.hi", C_TDP_RANGE.0.to_string() ).unwrap();

    //Allow config ranges to override default values
    let trip_temp_range_low = settings.get_float("trip_temp_range.low").unwrap();
    let trip_temp_range_hi = settings.get_float("trip_temp_range.hi").unwrap();
    
    // config values sanity check
    // I.E: All values should be higher than 0.1
    for power_source in ["AC", "BATTERY"].iter() {
        for option in [
                "Update_Rate_s",
                "PL1_Tdp_W",
                "PL1_Duration_s",
                "PL2_Tdp_W",
                "PL2_Duration_S", ].iter() {
            settings.set(format!("{}.{}",power_source, option).as_str(), settings.get_float(format!("{}.{}",power_source, option).as_str()).unwrap().max(0.1).to_string());
        }
        let trip_temp = settings.get_float(format!("{}.Trip_Temp_C",power_source).as_str()).unwrap();
        let valid_trip_temp = trip_temp_range_hi.min(trip_temp.max(trip_temp_range_low));
        if trip_temp != valid_trip_temp {
            settings.set(format!("{}.Trip_Temp_C",power_source).as_str(), valid_trip_temp);
            println!("[!] Overriding invalid 'Trip_Temp_C' value in {}: {:.1} -> {:.1}",power_source, trip_temp, valid_trip_temp);
        }
    }

    //No undervolt value is greater than 0
    for plane in VOLTAGE_PLANES {
        let value = settings.get_float(format!("UNDERVOLT.{}",plane.0).as_str()).unwrap();
        let valid_value = value.min(0.0);
        if value != valid_value {
            settings.set(format!("UNDERVOLT.{}", plane.0).as_str(), valid_value);
            println!("[!] Overriding invalid 'UNDERVOLT' value in {} voltage plane: {:.0} -> {:.0}",plane.0, value, valid_value);
        }
    }

    return settings;
}

fn calc_reg_values(config: Config) -> HashMap<(String,String), u64> {
    let mut regs: HashMap<(String,String), u64> = HashMap::new();
    for power_source in ["AC", "BATTERY"].iter() {
        let read_data = readmsr(0xce, 30, 30);
        //Flatten = false, cpu = 0
        if read_data[0] != 1 {
            println!("[W] Setting temperature target is not supported by this CPU");
        } else {
            // the critical temperature for my CPU is 100 'C
            let critical_temp = readmsr(0x1a2, 16, 23)[0] as i64;
            // Flatten = false, cpu = 0
            // update the allowed temp range to keep at least 3 'C from the CPU critical temperature
            config.set("trip_temp_range.hi", config.get_int("trip_temp_range.hi").unwrap().min(critical_temp - 3));

            let trip_offset = critical_temp as u64 - config.get_float(format!("{}.Trip_Temp_C",power_source).as_str()).unwrap().round() as u64;
            regs.insert((power_source.to_string(),String::from("MSR_TEMPERATURE_TARGET")), trip_offset << 24);
        }
        // 0.125 is the power unit of my CPU
        let power_unit = 1.0 / 2f64.powi(readmsr(0x606, 0, 3)[0] as i32);
        // Flatten = false, cpu = 0
        let PL1 = (config.get_float(format!("{}.PL1_Tdp_W",power_source).as_str()).unwrap() / power_unit).round() as u64;
        let ( Y, Z ) = calc_time_window_vars(config.get_float(format!("{}.PL1_Duration_s",power_source).as_str()).unwrap());
        let TW1 = Y | (Z << 5);

        let PL2 = (config.get_float(format!("{}.PL2_Tdp_W",power_source).as_str()).unwrap() / power_unit).round() as u64;
        let ( Y, Z ) = calc_time_window_vars(config.get_float(format!("{}.PL2_Duration_s",power_source).as_str()).unwrap());
        let TW2 = Y | (Z << 5);

        regs.insert((power_source.to_string(),"MSR_PKG_POWER_LIMIT".to_string()), PL1 | (1 << 15) | (TW1 << 17) | (PL2 << 32) | (1 << 47) | ( TW2 << 49));
        
        // cTDP
        let c_tdp_target_value = config.get_int(format!("{}.cTDP", power_source).as_str());
        let c_tdp_range_low = config.get_int("c_tdp_range.lo").unwrap();
        let c_tdp_range_hi = config.get_int("c_tdp_range.hi").unwrap();

        if c_tdp_target_value.is_ok() {
            if readmsr(0xce, 33, 34)[0] < 2 {
                // Flatten = false, cpu = 0
                println!("[W] cTDP setting not supported by this CPU");
            } else {
                let valid_c_tdp_target_value = c_tdp_range_hi.min(c_tdp_range_low.max(c_tdp_target_value.unwrap()));
                regs.insert((power_source.to_string(),"MSR_CONFIG_TDP_CONTROL".to_string()),valid_c_tdp_target_value as u64);
            }
        }
    }
    return regs;
}

fn calc_time_window_vars(t:f64) -> (u64, u64) {
    // 0.000977 is the time unit of my CPU
    // TODO: Is this cast to i32 safe?
    let time_unit = 1.0 / 2f64.powi(readmsr(0x606, 16, 19)[0] as i32);
    for Y in 1..2u64.pow(5) {
        for Z in 1..2u64.pow(2) {
            if t <= (2f64.powi(Y as i32)) * (1.0 + Z as f64 / 4.0) * time_unit {
                return (Y, Z);
            }
        }
    }
    panic!("[E]Unable to find a good combination!");
}

fn set_hwp(pref:String) {
    // set HWP energy performance hints
    // TODO: Does this string compare really work?
    assert!(["performance", "balance_performance", "default", "balance_power", "power"].iter().any(|x| x == &pref.as_str()));
    for c in glob("/sys/devices/system/cpu/cpu[0-9]*/cpufreq/energy_performance_preference").expect("Failed to read from sysfs glob pattern") {
        match c {
            Ok(path) => {
                let mut file = File::create(path).unwrap();
                file.write_all(pref.as_bytes());
                file.sync_all();
            },
            Err(e) => println!("{:?}",e),
        }
    }
}

fn power_thread(config: Config, regs: HashMap<(String,String),u64>, exit_event: mio::Evented, power: HashMap<&str,&str>) {
    let mut mmap_options = memmap::MmapOptions::new().offset(0xfed159a0).len(8);
    let mut mmap = match mmap_options.map_mut(&File::open("/dev/mem").unwrap()) {
        Ok(m) => m,
        Err(e) => panic!("[E] Couldn't allocate memorymap: {}",e),
    };
    let mut read_buf = [0u8; 8];
    (&mmap[..]).read(&mut read_buf);

    let debug = config.get_bool("General.debug").unwrap();

    while !exit_event.is_set() {
        // switch back to sysfs polling
        if *power.get("method").unwrap() == "polling" {
            *power.get_mut("source").unwrap() = if is_on_ac(config) {"AC"} else {"BATTERY"};
        }

        // set temperature trip point
        if regs.contains_key(&(power["source"].to_string(),"MSR_TEMPERATURE_TARGET".to_string())) {
            let write_value = regs.get(&(power["source"].to_string(),"MSR_TEMPERATURE_TARGET".to_string())).unwrap();
            writemsr(0x1a2, *write_value);
            if debug {
                let read_value = readmsr(0x1a2, 24, 29);
                // Flatten = true, Cpu = none
                let mat = *write_value >> 24 == read_value;
                println!("[D] TEMPERATURE_TARGET - write {:?} - read {:?} - match {:?}",
                    write_value >> 24, read_value, mat);
            }
        }

        // set cTDP
        if regs.contains_key(&(power["source"].to_string(),"MSR_CONFIG_TDP_CONTROL".to_string())) {
            let write_value = regs.get(&(power["source"].to_string(),"MSR_CONFIG_TDP_CONTROL".to_string())).unwrap();
            writemsr(0x64b, *write_value);
            if debug {
                let read_value = readmsr(0x64b, 0, 1);
                // Flatten = true, Cpu = none
                let mat = *write_value == read_value;
                println!("[D] CONFIG_TDP_CONTROL - write {:?} - read {:?} - match {}",
                    write_value, read_value, mat);
            }
        }

        // set PL1/2 on MSR
        let write_value = regs.get(&(power["source"].to_string(),"MSR_PKG_POWER_LIMIT".to_string())).unwrap();
        writemsr(0x610, *write_value);
        if debug {
            let read_value = readmsr(0x610, 0, 55);
            // Flatten = true, Cpu = none
            let mat = *write_value == read_value;
            println!("[D] MSR PACKAGE_POWER_LIMIT - write {:?} - read {:?} - match {}",
                write_value, read_value, mat);
        }

        // set MCHBAR register to the same PL1/2 values
        mchbar_mmio.write32(0, write_value & 0xffffffff);
        mchbar_mmio.write32(4, write_value >> 32);
        if debug {
            let read_value = mchbar_mmio.read32(0) | (mchbar_mmio.read32(4) << 32);
            let mat = write_value == read_value;
            println!("[D] MCHBAR PACKAGE_POWER_LIMIT - write {:?} - read {:?} - match {}",
                write_value, read_value, mat);
        }

        let wait_t = config.get_float(format!("{}.Update_Rate_s",power["source"]).as_str()).unwrap();
        let enable_hwp_mode = config.get_bool("AC.HWP_Mode").unwrap();
        if power["source"] == "AC" && enable_hwp_mode {
            let cpu_usage = psutil::system::cpu_percent(wait_t).unwrap();
            // set full performance mode only when load is greater than this threshold (~ at least 1 core full speed)
            let performance_mode = cpu_usage > 100.0 / (num_cpus::get() as f64 * 1.25);
            // check again if we are on AC, since in the meantime we might have switched to BATTERY
            if is_on_ac(config) {
                set_hwp(if performance_mode {"performance".to_string()} else {"balance_performance".to_string()});
            } else {
                exit_event.wait(wait_t);
            }
        }
    }
}