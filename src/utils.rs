//use crate::ArrType;
use crate::defs::ArrType;

pub fn cmp_array_string(string1: &str, array: &[i8]) -> u8 {
    let mut name = String::from("");
    for n in array {
        let new = *n as u8;
        //println!("{}", *n);
        if *n == 0 {
            break;
        }
        name.push(new as char);
    }

    log::debug!("cmp_array_string | module name: {}", name);
    let back = if name == string1 {
        1
    } else if name == "?" {
        2
    } else {
        0
    };

    // println!("Array: {:?}",array);
    // print!("");
    drop(name);
    back
}

pub fn str_arr(s: &str) -> ArrType {
    log::debug!("str_arr | converting Str to Char Array: {}", s);
    let mut arr1: ArrType = [0; 250];
    for (a, c) in arr1.iter_mut().zip(s.bytes()) {
        *a = c as i8;
    }
    return arr1;
}
