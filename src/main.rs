extern crate sysinfo;

use std::env;
use std::str;
use std::thread;
use std::time::Duration;
use std::collections::HashMap;

use redis::FromRedisValue;
use pnet::datalink;
use sysinfo::{ProcessorExt, System, SystemExt};

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
    let args: Vec<String> = env::args().collect();

    let netif = &args[1];
    let redisaddr = &args[2];

    let rd_client = redis::Client::open(format!("redis://{}", redisaddr)).unwrap();
    let mut rdconn = rd_client.get_connection().unwrap();

    let own_addr = ip_find(netif);

    match redis::cmd("SMEMBERS")
        .arg(&["nodes"])
        .query(&mut rdconn)
        .expect("could not execute redis command")
    {
        redis::Value::Bulk(a) => {
            for i in 0..a.len() {
                match FromRedisValue::from_redis_value(&a[i]) {
                    Ok(redis::Value::Data(d)) => {
                        if own_addr == str::from_utf8(&d).unwrap().to_string() {
                            break;
                        }
                    }
                    Err(e) => panic!("{}", e),
                    _ => panic!("error")
                }
                if i == a.len() { panic!("this computer is not member of cluster.") }
            }
            
        }
        _ => panic!("error"),
    };

    let mut sys = System::new_all();

    loop {
        sys.refresh_all();

        let hostname = sys.host_name().unwrap();
        let os_type = sys.long_os_version().unwrap();
        let os_release = sys.kernel_version().unwrap();
        //let cpu_arch = host::info().architecture().as_str().to_string();
        let cpu_num = sys.physical_core_count().unwrap();
        let cpu_speed = sys.global_processor_info().frequency();
        let proc_total = sys.processes().len();
        let mut cpu_usage: HashMap<String, f32> = HashMap::new();
        let load_one: f64 = sys.load_average().one;
        let load_five: f64 = sys.load_average().five;
        let load_fifteen: f64 = sys.load_average().fifteen;
        let mem_total: u64 = sys.total_memory();
        let mem_free: u64 = sys.free_memory();

        for proc in sys.processors() {
            cpu_usage.insert(proc.name().to_string(), proc.cpu_usage());
            let _ = redis::cmd("HSET")
                .arg(&[format!("{}_cpu_usage", own_addr.clone()), proc.name().to_string(), proc.cpu_usage().to_string()])
                .query::<i32>(&mut rdconn);
        }

        let _ = redis::cmd("HSET")
            .arg(&[format!("{}_status", own_addr.clone()), "hostname".to_string(), hostname])
            .query::<i32>(&mut rdconn);
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
