from beldex.address import address ,Address, SubAddress, IntegratedAddress

def check_mainnet_address(addr_str):
    try:
        a = address(addr_str)

        print("Address:", a)
        print("Network:", a.net)
        if isinstance(a, Address):
            print("Type: Primary Address")
        elif isinstance(a, SubAddress):
            print("Type: Subaddress")

        elif isinstance(a, IntegratedAddress):
            print("Type: Integrated Address")
            print("Payment ID:", a.payment_id())

        print("Public Spend Key:", a.spend_key())
        print("Public View Key:", a.view_key())


    except Exception as e:
        print("❌ Invalid Beldex address")
        print("Error:", e)


if __name__ == "__main__":
    user_input = input("Enter Beldex address: ").strip()
    check_mainnet_address(user_input)
