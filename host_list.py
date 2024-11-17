hosts = {
    "client": 1,
    "server": 2,
    "pka": 3,
}

def get_host_id(server_name):
    return hosts.get(server_name, "Server not found")


# Example usage
if __name__ == "__main__":
    # Test the function
    test_server_name = "pka"
    print(f"Server ID for '{test_server_name}': {get_host_id(test_server_name)}")