from turbo_sticks.csrf import TokenClerk, sign_token


def test_sign_token():
    token = '01234567'*4
    signed = sign_token(token, 0.0, 'deadbeef'*16)
    assert len(signed) == 64
    assert signed[:32] == token
    assert signed == sign_token(token, 0.0, 'deadbeef'*16)
    assert signed == sign_token(signed, 0.0, 'deadbeef'*16)
    assert signed != sign_token(token, 0.0, 'deedbeef'*16)
    assert signed != sign_token(signed, 0.0, 'deedbeef'*16)
    assert signed != sign_token(token, 1.0, 'deadbeef'*16)
    assert signed != sign_token(signed, 0.0, 'deedbeef'*16)


def test_token_clerk_flush_if_necessary(time_machine, monkeypatch):
    orig = TokenClerk._flush_if_necessary
    flush_counter = 0

    def count_if_flushed(self):
        nonlocal flush_counter
        next_flush_before = self.next_flush
        orig(self)
        if self.next_flush != next_flush_before:
            flush_counter += 1

    monkeypatch.setattr(TokenClerk, '_flush_if_necessary', count_if_flushed)

    time_machine.move_to(0, tick=False)
    session = 'deadbeef'*16
    clerk = TokenClerk()
    csrf_token = clerk.register(session)
    assert len(clerk.tokens) == 1
    assert csrf_token in clerk.tokens
    assert clerk.tokens[csrf_token] == 3600.0

    # trigger flush by moving forward 5 minutes
    time_machine.move_to(300.0, tick=False)
    assert csrf_token != clerk.register(session)
    assert flush_counter == 1
    assert len(clerk.tokens) == 2

    # trigger expiration on first token
    time_machine.move_to(3600.0, tick=False)
    assert clerk.validate(session, csrf_token) is False
    assert flush_counter == 2
    assert len(clerk.tokens) == 1
    assert csrf_token not in clerk.tokens

    # trigger expiration on other token
    time_machine.move_to(3900.0, tick=False)
    assert clerk.validate(session, None) is False
    assert flush_counter == 3
    assert len(clerk.tokens) == 0


def test_token_clerk_replay_attack():
    session = 'deadbeef'*16
    clerk = TokenClerk()
    csrf_token = clerk.register(session)
    assert clerk.validate(session, csrf_token) is True
    assert csrf_token not in clerk.tokens

    # replay won't work
    assert clerk.validate(session, csrf_token) is False
