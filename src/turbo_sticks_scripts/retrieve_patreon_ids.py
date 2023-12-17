# this only works if you've supplied a currently valid access and refresh token
# for patreon in the config
from turbo_sticks import patreon


def main() -> None:
    patreon.init_oauth()
    campaigns = patreon.get_campaigns()
    assert isinstance(campaigns, list)
    for campaign in campaigns:
        name = campaign['creation_name']
        cid = campaign['id']
        print('========================================')
        print(f'Campaign: {name} ({cid})')
        tiers = campaign['tiers']
        assert isinstance(tiers, list)
        for tier in tiers:
            assert isinstance(tier, dict)
            dollars = tier['amount_cents'] // 100  # type:ignore[operator]
            title = tier['title']
            tid = tier['id']
            print(f'    Tier: ${dollars}+ {title} ({tid})')
        print('========================================')


if __name__ == '__main__':
    main()
