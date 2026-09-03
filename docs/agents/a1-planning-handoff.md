# A1 Planning Handoff

## Stop point

Planning is complete. Application implementation has not started. Resume from branch `isaaclares-it401-a1` after reading `CONTEXT.md` and `docs/adr/0001-use-static-demonstration-data-for-a1.md`.

The shared-understanding commit is `3005d2a` (`docs: define BuzzAware Campus concept`). The branch is local and has not yet been pushed to GitHub.

## Confirmed direction

Build **BuzzAware Campus**, a Flask application for CSUCI students, faculty, staff, and visitors. Its `/explore` page will load fictional demonstration observations for eight CSUCI Campus Areas from JSON and filter them by reported activity level and location type. The page will also provide source-linked educational cards about mosquito identification, bite prevention, and reducing breeding sites.

The interface must state that its observations are demonstration data rather than official CSUCI or public-health surveillance. Use *reported activity*—Low, Moderate, or High—and never present those levels as disease risk.

The initial dataset uses the eight locations listed in `CONTEXT.md`. Preserve an extensible Campus Area model so later versions can add building-level locations such as Sierra Hall and Gateway Hall.

## Next session

Start by reviewing the assignment requirements against the existing template. Then implement A1 test-first on `isaaclares-it401-a1`, including:

1. Shared `base.html` layout with title, navigation, stylesheet, and footer.
2. Customized homepage with the agreed name, tagline, description, student attribution, SVG mosquito/map-pin logo, and Explore Activity call to action.
3. JSON datastore containing the eight demonstration Campus Areas.
4. `/explore` route with validated GET filters, severity-first ordering, result count, clear-filter behavior, and no-results state.
5. CDC-backed educational cards with source links and the demonstration-data disclosure.
6. Tests for routes, JSON display, filter combinations, invalid filter values, ordering, and empty results.
7. Assignment-specific README sections and screenshot placeholders.
8. Browser verification, screenshots, and the required submission PDF.

Do not treat the current `ApiService`, `AiService`, or placeholder `SearchService` as required for A1 unless the implementation reveals a clear need.

## Resume prompt

> Continue A1 from `docs/agents/a1-planning-handoff.md`. Read `CONTEXT.md` and ADR 0001 first, inspect the current branch, and implement BuzzAware Campus test-first. Stop before pushing or performing other external actions unless I explicitly approve them.
