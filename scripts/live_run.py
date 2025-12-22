from vireon_miner.live_client import LiveConfig, run_live

def main():
    cfg = LiveConfig(
        host="stratum.solopool.com",
        port=3334,
        username="tb1PUT_TESTNET4_ADDRESS_HERE.vireon1",
        password="x",
        batch_nonces=200_000,
        suggest_difficulty=1.0,
    )
    run_live(cfg)

if __name__ == "__main__":
    main()
