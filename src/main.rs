use ntapi::ntpebteb::{
    API_SET_HASH_ENTRY, API_SET_NAMESPACE, API_SET_NAMESPACE_ENTRY, API_SET_VALUE_ENTRY,
};
use ntapi::ntpsapi::NtCurrentPeb;
use pelite::pe64::{Pe, PeFile};
use pelite::FileMap;
use std::cmp::Ordering;
use std::ffi::OsString;
use std::os::windows::prelude::OsStringExt;

fn is_api_set_dll(name: &str) -> bool {
    if name.contains("api-") || name.contains("ext-") {
        return true;
    }
    false
}

fn get_dll_name_without_extension(name: &str) -> String {
    let last_hyphen_index = name.rfind('-').unwrap();

    name[..last_hyphen_index].to_owned()
}

fn get_dll_name_hash(api_set_map: *const API_SET_NAMESPACE, name: &str) -> u32 {
    let mut hash_key: u32 = 0;
    unsafe {
        for c in name.to_ascii_lowercase().chars() {
            hash_key = hash_key
                .wrapping_mul((*api_set_map).HashFactor)
                .wrapping_add(c as u32);
        }
    }
    hash_key
}

fn get_api_set_hash_entry(
    api_set_map: *const API_SET_NAMESPACE,
    hash_index: u32,
) -> *const API_SET_HASH_ENTRY {
    unsafe {
        (api_set_map as usize
            + (*api_set_map).HashOffset as usize
            + std::mem::size_of::<u64>() * hash_index as usize) as *const API_SET_HASH_ENTRY
    }
}

fn get_api_set_namespace_entry(
    api_set_map: *const API_SET_NAMESPACE,
    hash_index: u32,
) -> *const API_SET_NAMESPACE_ENTRY {
    unsafe {
        (api_set_map as usize
            + (*get_api_set_hash_entry(api_set_map, hash_index)).Index as usize
                * std::mem::size_of::<API_SET_NAMESPACE_ENTRY>()
            + (*api_set_map).EntryOffset as usize) as *const API_SET_NAMESPACE_ENTRY
    }
}

// returns the name used for calculating the hash key
fn get_api_set_hash_name_of_entry(
    api_set_map: *const API_SET_NAMESPACE,
    entry: *const API_SET_NAMESPACE_ENTRY,
) -> String {
    unsafe {
        let name_ptr = (api_set_map as usize + (*entry).NameOffset as usize) as *const u16;
        let name_lenght = (*entry).HashedLength / 2;
        // For some reason microsoft decided that Length == Size, so in order to get the real Lenght, we need to divided by 2
        let name_slice = std::slice::from_raw_parts(name_ptr, name_lenght as usize);
        let os_str: OsString = OsStringExt::from_wide(name_slice);
        os_str.to_string_lossy().to_string()
    }
}

fn get_api_set_value_entry(
    api_set_map: *const API_SET_NAMESPACE,
    entry: *const API_SET_NAMESPACE_ENTRY,
    index: usize,
) -> *const API_SET_VALUE_ENTRY {
    unsafe {
        (api_set_map as usize
            + index * std::mem::size_of::<API_SET_VALUE_ENTRY>()
            + (*entry).ValueOffset as usize) as *const API_SET_VALUE_ENTRY
    }
}

fn get_api_set_value_of_entry_value(
    api_set_map: *const API_SET_NAMESPACE,
    entry: *const API_SET_VALUE_ENTRY,
) -> String {
    unsafe {
        let name_ptr = (api_set_map as usize + (*entry).ValueOffset as usize) as *const u16;
        let name_lenght = (*entry).ValueLength / 2;
        // For some reason microsoft decided that Length == Size, so in order to get the real Lenght, we need to divided by 2
        let name_slice = std::slice::from_raw_parts(name_ptr, name_lenght as usize);
        let os_str: OsString = OsStringExt::from_wide(name_slice);
        os_str.to_string_lossy().to_string()
    }
}

fn get_api_set_redirect_by_hash(
    hash: u32,
    api_set_map: *const API_SET_NAMESPACE,
    name_without_extension: &str,
) -> Option<*const API_SET_VALUE_ENTRY> {
    unsafe {
        let mut lower_bound = 0;
        let mut upper_bound = (*api_set_map).Count;
        while lower_bound < upper_bound {
            let mid_index = (lower_bound + upper_bound) / 2;
            let api_set_hash_entry = get_api_set_hash_entry(api_set_map, mid_index);

            match hash.cmp(&(*api_set_hash_entry).Hash) {
                Ordering::Equal => {
                    let found_entry = get_api_set_namespace_entry(api_set_map, mid_index);
                    if found_entry.is_null() {
                        return None;
                    }
                    let entry_name = get_api_set_hash_name_of_entry(api_set_map, found_entry);

                    // Here is the fun part!
                    //  Example:
                    //  Original dll name:                                  "api-ms-win-crt-runtime-l1-1-0.dll"
                    //  Dll name that is used for calculating the hash key: "api-ms-win-crt-runtime-l1-1"
                    //  Dll name that is sitting in api set memory:         "api-ms-win-crt-runtime-l1-1-0"
                    //  c:
                    //  So in order to get a corresponding name for a comparison,
                    //  get_api_set_value_hash_name returns the name used for calculating the hash key

                    if entry_name == name_without_extension && ((*found_entry).ValueCount > 0) {
                        return Some(get_api_set_value_entry(api_set_map, found_entry, 0));
                    }
                    // If the names don't match, it means we have a hash collision
                    // We need to decide how to handle it, for now, let's continue searching
                    lower_bound = mid_index + 1;
                }
                Ordering::Less => upper_bound = mid_index,
                Ordering::Greater => lower_bound = mid_index + 1,
            }
        }
        println!("Couldn't find entry with hash!");
    }
    None
}

fn main() {
    let file_map = match FileMap::open("Pengu.dll") {
        Ok(file) => file,
        Err(err) => panic!("{}", err),
    };

    let pe_file = PeFile::from_bytes(file_map.as_ref()).unwrap();
    let imports = pe_file.imports().unwrap();

    unsafe {
        let api_set_map = (*NtCurrentPeb()).ApiSetMap;
        println!("api_set_map = 0x{:X}", api_set_map as usize);

        for desc in imports {
            let dll_name = desc.dll_name().unwrap().to_str().unwrap();
            println!("dll_name = {}", dll_name);

            if is_api_set_dll(dll_name) {
                let stripped_name = get_dll_name_without_extension(dll_name);
                println!("stripped_name = {}", stripped_name);

                let hash = get_dll_name_hash(api_set_map, &stripped_name);
                let entry = get_api_set_redirect_by_hash(hash, api_set_map, &stripped_name);

                match entry {
                    Some(item) => println!(
                        "Found entry = {}",
                        get_api_set_value_of_entry_value(api_set_map, item)
                    ),
                    None => println!("Couldn't find the correct entry :c"),
                }

                for import in desc.int().unwrap() {
                    println!("\t{:?}", import)
                }
            }
        }
    };
}
