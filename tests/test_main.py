from unittest.mock import patch

from nettacker import main


def test_main_invokes_nettacker_run():
    with patch("nettacker.main.Nettacker") as mock_nettacker:
        main.run()

    mock_nettacker.assert_called_once()
    mock_nettacker.return_value.run.assert_called_once()
