# BuzzAware Campus Domain Context

## Purpose

BuzzAware Campus helps CSUCI students, faculty, staff, and visitors understand which campus areas have higher reported mosquito activity and choose sensible precautions before visiting them.

The Assignment 1 application uses fictional demonstration observations. It is not an official CSUCI, vector-control, medical, or public-health surveillance service.

## Ubiquitous Language

### Campus Area

A recognizable public place at CSUCI that can appear in the activity explorer. A Campus Area may be an academic building, recreation area, residential area, dining destination, or outdoor gathering space.

Assignment 1 begins with eight Campus Areas: John Spoor Broome Library, Bell Tower, Islands Cafe, Town Center, North Quad, South Quad, Potrero Field, and Santa Cruz Village. The model must remain easy to extend with building-level locations such as Sierra Hall and Gateway Hall.

Attributes:

- `name`: public CSUCI location name
- `location_type`: Academic, Recreation, Residential, Dining, or Outdoor
- `activity_level`: Low, Moderate, or High reported activity
- `observation_date`: date associated with the sample observation
- `description`: short explanation of the location and observation
- `precaution`: practical action a visitor could take

### Reported Activity

A qualitative classification of mosquito observations associated with a Campus Area. The allowed values are Low, Moderate, and High. It describes demonstration mosquito activity, not disease risk.

### Activity Explorer

The `/explore` page that reads Campus Areas from JSON, displays higher activity first, and lets users filter by activity level and location type. An empty result explains that no areas match and offers to clear the filters.

### Guide Card

A short educational item displayed with the Activity Explorer. Assignment 1 covers mosquito identification, bite prevention, and reducing breeding sites using authoritative public-health sources.

### Community Sighting Report

A future user-submitted observation about mosquito activity at a Campus Area. Reports are not part of Assignment 1. A later version will persist and validate or moderate them before treating them as trustworthy observations.

## Product Language

- Application name: **BuzzAware Campus**
- Tagline: **Know where mosquitoes are active before you go.**
- Primary action: **Explore Activity**
- Disclosure: **Demonstration data—not official CSUCI or public-health surveillance.**

## Future Direction

Assignment 2 should prioritize persistent community sighting reports. Later work may add external weather or vector-control information, search, additional buildings, and map-based decision support.

## Information Sources

- [CSUCI campus map](https://maps.csuci.edu/?id=502)
- [CSUCI outdoor spaces](https://www.csuci.edu/office-departments/university-events/locations/athletic-outdoor-spaces.html)
- [CSUCI recreation fields](https://www.csuci.edu/student-life/recreation/rec-fields.html)
- [CSUCI housing](https://www.csuci.edu/student-life/housing/index.html)
- [CSUCI Sierra Hall](https://www.csuci.edu/fs/pdc/sierra-hall.htm)
- [CSUCI Gateway Hall opening](https://www.csuci.edu/news/releases/gateway-hall-opening-20250822.htm)
- [CDC mosquito overview](https://www.cdc.gov/mosquitoes/about/index.html)
- [CDC mosquito-bite prevention](https://www.cdc.gov/mosquitoes/prevention/index.html)
- [CDC mosquito control at home](https://www.cdc.gov/mosquitoes/mosquito-control/mosquito-control-at-home.html)
