<?php

declare(strict_types=1);

namespace DarkSide\OpenIdConnectServer\League;

enum RefreshTokenConsumptionResult
{
    case CONSUMED;
    case REPLAYED;
    case INVALID;
}
