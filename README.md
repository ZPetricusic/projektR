## Restrictions

-   GSB_API=10000 requests/day -> ~10s/req

End data object:

```json
{
	"results": [
		{
			"domain1": {
				"ip_data": [
					{
						"127.0.0.1": {
							"scores": {
								"x_score": 0
							}
						}
					},
					{
						"127.0.0.5": {
							"scores": {
								"x_score": 0
							}
						}
					}
				],
				"endpoint_data": [
					{
						"/login": {
							"scores": {
								"GSB_score": 0
							}
						}
					},
					{
						"/logout": {
							"scores": {
								"GSB_score": 0
							}
						}
					}
				]
			}
		},
		{
			"domain2": {
				"ip_data": [
					{
						"127.0.0.1": {
							"scores": {
								"x_score": 0
							}
						}
					},
					{
						"127.0.0.5": {
							"scores": {
								"x_score": 0
							}
						}
					}
				],
				"endpoint_data": [
					{
						"/login": {
							"scores": {
								"GSB_score": 0
							}
						}
					},
					{
						"/logout": {
							"scores": {
								"GSB_score": 0
							}
						}
					}
				]
			}
		}
	]
}
```
