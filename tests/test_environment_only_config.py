from gateway.config import Settings, get_settings

def test_explicit_environment_only_mode_does_not_read_dotenv(monkeypatch, tmp_path):
    sample = tmp_path / '.env'
    sample.write_text('FEISHU_APP_ID=synthetic-dotenv-value\n', encoding='utf-8')
    monkeypatch.setitem(Settings.model_config, 'env_file', str(sample))
    monkeypatch.delenv('FEISHU_APP_ID', raising=False)
    monkeypatch.setenv('NACHUAN_CONFIG_ENV_ONLY', '1')
    get_settings.cache_clear()
    try:
        assert get_settings().feishu_app_id == ''
        monkeypatch.delenv('NACHUAN_CONFIG_ENV_ONLY')
        get_settings.cache_clear()
        assert get_settings().feishu_app_id == 'synthetic-dotenv-value'
    finally:
        get_settings.cache_clear()
