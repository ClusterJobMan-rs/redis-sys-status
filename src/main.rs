use std::thread;
use std::time::Duration;

use pnet::datalink;
use sys_info::*;
use systemstat::*;

fn ip_find(interface_name: &str) -> String{
    for iface in datalink::interfaces() {
        let ips = iface.ips;
        let mut i = 0;
        if !(iface.name == "lo") {
            for ip in ips { 
                if i == 0 {
                    let addr = ip.to_string();
                    if iface.name == interface_name {
                        let addr_fixed: Vec<&str> = addr.split("/").collect();
                        return addr_fixed[0].to_string();
                    }
                }
                i += 1;
            }
        }
    }
    return "".to_string();
}

fn main() {
    let rd_client = redis::Client::open("redis://127.0.0.1").unwrap();
    let mut rdconn = rd_client.get_connection().unwrap();

    let own_addr = ip_find("eth0");

    let _ = redis::Cmd::sadd("nodes", own_addr.clone())
        .query::<i32>(&mut rdconn);

    loop {
        let sys = systemstat::System::new();

        let os_type = os_type().unwrap();
        let os_release = os_release().unwrap();
        let cpu_num = cpu_num().unwrap();
        let cpu_speed = cpu_speed().unwrap();
        let proc_total = proc_total().unwrap();
        let mut cpu_user: f32 = 0.0;
        let mut cpu_nice: f32 = 0.0;
        let mut cpu_system: f32 = 0.0;
        let mut cpu_idle: f32 = 0.0;
        let mut load_one: f32 = 0.0;
        let mut load_five: f32 = 0.0;
        let mut load_fifteen: f32 = 0.0;
        let mut mem_total: u64 = 0;
        let mut mem_free: u64 = 0;

        match sys.cpu_load_aggregate() {
            Ok(cpu) => {
                thread::sleep(Duration::from_secs(1));
                let cpu = cpu.done().unwrap();
                cpu_user = cpu.user;
                cpu_nice = cpu.nice;
                cpu_system = cpu.system;
                cpu_idle = cpu.idle;
            }
            Err(x) => println!("CPU load error: {}", x)
        }

        match sys.load_average() {
            Ok(load) => {
                load_one = load.one;
                load_five = load.five;
                load_fifteen = load.fifteen;
            },
            Err(x) => println!("Load average error: {}", x)
        }

        match sys.memory() {
            Ok(mem) => {
                mem_total = mem.total.0;
                mem_free = mem.free.0;
            }
            Err(x) => println!("Memory Error: {}", x)
        }

        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "os_type".to_string(), os_type])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_release".to_string(), os_release])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_num".to_string(), cpu_num.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_speed".to_string(), cpu_speed.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "proc_total".to_string(), proc_total.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_user".to_string(), cpu_user.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_nice".to_string(), cpu_nice.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_system".to_string(), cpu_system.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "cpu_idle".to_string(), cpu_idle.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "load_one".to_string(), load_one.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "load_five".to_string(), load_five.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "load_fifteen".to_string(), load_fifteen.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "mem_total".to_string(), mem_total.to_string()])
            .query::<i32>(&mut rdconn);
        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "mem_free".to_string(), mem_free.to_string()])
            .query::<i32>(&mut rdconn);
    
        thread::sleep(Duration::from_secs(5));
    }
}
