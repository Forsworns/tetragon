// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Tetragon

package mapmetrics

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/tetragon/pkg/logger"
	"github.com/cilium/tetragon/pkg/metrics/consts"
	"github.com/cilium/tetragon/pkg/sensors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	MapSize = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "map_in_use_gauge",
		Help:        "The total number of in-use entries per map.",
		ConstLabels: nil,
	}, []string{"map", "total"})

	SensorMapsLoaded = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name:        consts.MetricNamePrefix + "sensor_maps_loaded",
		Help:        "The total number of copies of a sensor map that have been loaded into the kernel.",
		ConstLabels: nil,
	}, []string{"map_name"})
)

// Get a new handle on a mapSize metric for a mapName and totalCapacity
func GetMapSize(mapName string, totalCapacity int) prometheus.Gauge {
	return MapSize.WithLabelValues(mapName, fmt.Sprint(totalCapacity))
}

// Increment a mapSize metric for a mapName and totalCapacity
func MapSizeInc(mapName string, totalCapacity int) {
	GetMapSize(mapName, totalCapacity).Inc()
}

// Set a mapSize metric to size for a mapName and totalCapacity
func MapSizeSet(mapName string, totalCapacity int, size float64) {
	GetMapSize(mapName, totalCapacity).Set(size)
}

// UpdateSensorMapsLoaded updates the count of loaded sensor maps
func UpdateSensorMapsLoaded() {
	registeredMapNames := make(map[string]struct{})
	mapCounts := make(map[string]int)

	for _, m := range sensors.AllMaps {
		if m == nil {
			continue
		}
		// Map names in the kernel are truncated to 16 chars
		var truncatedName = m.Name
		if len(truncatedName) > 16 {
			truncatedName = truncatedName[:16]
		}
		registeredMapNames[truncatedName] = struct{}{}
		logger.GetLogger().WithField("name", m.Name).Debug("UpdateMapCounts: Found sensor map")
	}

	var id ebpf.MapID
	for {
		var err error
		id, err = ebpf.MapGetNextID(id)
		if err != nil {
			break
		}
		m, err := ebpf.NewMapFromID(id)
		if err != nil {
			logger.GetLogger().WithError(err).WithField("ID", id).Debug("UpdateMapCounts: Failed to create map from ID")
			continue
		}
		i, err := m.Info()
		if err != nil {
			logger.GetLogger().WithError(err).WithField("ID", id).Debug("UpdateMapCounts: Failed to get map info")
			continue
		}
		if _, ok := registeredMapNames[i.Name]; !ok {
			logger.GetLogger().WithField("ID", id).WithField("name", i.Name).Debug("UpdateMapCounts: Skipping non-sensor map")
			continue
		}
		logger.GetLogger().WithField("ID", id).WithField("name", i.Name).Debug("UpdateMapCounts: Incrementing metrics count for map")
		mapCounts[i.Name]++
	}

	for name, count := range mapCounts {
		SensorMapsLoaded.WithLabelValues(name).Set(float64(count))
	}
}
