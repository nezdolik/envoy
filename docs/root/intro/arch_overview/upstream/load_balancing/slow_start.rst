.. _arch_overview_load_balancing_slow_start:

Slow start mode
===============

Slow start mode is a configuration setting in Envoy to progressively increase amount of traffic for newly added upstream endpoints.
With no slow start enabled Envoy would send a proportional amount of traffic to new upstream ednpoints.
This could be undesirable for services that require warm up time to serve full production load and could result in request timeouts, loss of data and deteriorated user experience.

Slow start mode is a mechanism that affects load balancing weight of upstream endpoints and can be configured per upstream cluster.
Currently, slow start is supported in Round Robin and Least Request load balancer types.

Users can specify a :ref:`slow start window parameter<envoy_v3_api_field_config.cluster.v3.Cluster.CommonLbConfig.SlowStartConfig.slow_start_window>` (in seconds), so that if endpoint "cluster membership duration" (amount of time since it has joined the cluster) is within the configured window, it enters slow start mode.
During slow start window, load balancing weight of a particular endpoint will be scaled with time factor, e.g.:

.. math::

  NewWeight = {Weight*TimeFactor}

where,

.. math::

  TimeFactor = {(\frac{max(TimeSinceStartInSeconds,1)}{SlowStartWindowInSeconds})}^\frac{1}{Aggression}

  As time progresses, more and more traffic would be send to endpoint within slow start window.

:ref:`Aggression parameter<envoy_v3_api_field_config.cluster.v3.Cluster.CommonLbConfig.SlowStartConfig.aggression>` non-linearly affects endpoint weight and represents the speed of ramp-up.
By tuning aggression parameter, one could achieve polynomial or exponential speed for traffic increase.
Below simulation demonstrates how various values for aggression affect traffic ramp-up:

.. image:: /_static/slow_start_aggression.svg
   :width: 60%
   :align: center

Whenever a slow start window duration elapses, upstream endpoint exits slow start mode and gets regular amount of traffic acccording to load balanacing algorithm.
Its load balancing weight will no longer be scaled with runtime bias and aggression. Endpoint could also exit slow start mode in case it leaves the cluster.

To reiterate, endpoint enters slow start mode:
  * If no active healthcheck is configured per cluster, immediately if its cluster membership duration is within slow start window.
  * In case an active healthcheck is configured per cluster, when its cluster membership duration is within slow start window and endpoint has passed an active healthcheck.
    If endpoint does not pass an active healcheck during entire slow start window (since it has been added to upstream cluster), then it never enters slow start mode.

Endpoint exits slow start mode when:
  * It leaves the cluster.
  * Its cluster membership duration is greater than slow start window.
  * It does not pass an active healcheck configured per cluster.
    Endpoint could further re-enter slow start, if it passes an active healtcheck and its creation time is within slow start window.

It is not recommended to enable slow start mode in low traffic or high number of endpoints scenarios, potential drawbacks would be:
 * Endpoint starvation, where endpoint has low probability to receive a request either due to low traffic or high number of total endpoints.
 * Spurious (non-gradual) increase of traffic per endpoint, whenever a starving endpoint receives a request and sufficient time has passed within slow start window,
   its load balancing weight will increase non linearly due to time factor.

Below is example of how requests would be distributed across endpoints in same priority with Round Robin Loadbalancer, slow start window of 60 seconds, no active healcheck, 0.5 time bias and 1.0 aggression.
Endpoints E1 and E2 have statically configured initial weight of X, the actual numerical value is of no significance for this example.

+-------------+--------------------+------------+------------+-----------+----------+-------------+
| Timestamp   | Event              | E1 in slow | E2 in slow | E1 LB     | E2 LB    | LB decision |
| in seconds  |                    | start      | start      | weight    | weight   |             |
+=============+====================+============+============+===========+==========+=============+
| 1           |  E1 create         |    YES     |     --     |   0.01X   |    --    |     --      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 20          |  Priority update   |    YES     |     --     |   0.33X   |    --    |     --      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 61          |  E2 create         |    NO      |    YES     |     X     |   0.01X  |     --      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          |  Priority update   |    NO      |    YES     |     X     |   0.16X  |     --      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          | LB select endpoint |    NO      |    YES     |     X     |   0.16X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          | LB select endpoint |    NO      |    YES     |     X     |   0.16X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          | LB select endpoint |    NO      |    YES     |     X     |   0.16X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          |LB select endpoint  |    NO      |    YES     |     X     |   0.16X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          | LB select endpoint |    NO      |    YES     |     X     |   0.16X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 81          | LB select endpoint |    NO      |    YES     |     X     |   0.16X  |     E2      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 116         | Priority update    |    NO      |    YES     |     X     |   0.45X  |     E2      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 116         | LB select endpoint |    NO      |    YES     |     X     |   0.45X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 116         | LB select endpoint |    NO      |    YES     |     X     |   0.45X  |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 116         | LB select endpoint |    NO      |    YES     |     X     |   0.45X  |     E2      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 125         | Priority update    |    NO      |    NO      |     X     |     X    |     --      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 116         | LB select endpoint |    NO      |    NO      |     X     |     X    |     E1      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
| 116         | LB select endpoint |    NO      |    YES     |     X     |     X    |     E2      |
+-------------+--------------------+------------+------------+-----------+----------+-------------+
