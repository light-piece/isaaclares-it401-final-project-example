# ADR 0001: Use Static Demonstration Data for Assignment 1

- Status: Accepted
- Date: 2026-09-03

## Context

BuzzAware Campus needs to display and filter mosquito activity information for CSUCI locations in Assignment 1. The application does not yet have verified observations, persistent storage, moderation, or an official CSUCI or public-health data connection.

Presenting invented observations as current facts could mislead campus users. Building a trustworthy live-reporting system would also exceed Assignment 1's scope.

## Decision

Assignment 1 will load a small set of fictional Campus Area observations from a JSON file. The interface will label them as demonstration data and describe levels as Low, Moderate, or High **reported activity**, never disease risk.

The Activity Explorer will use server-rendered GET filtering by activity level and location type. Educational cards will summarize authoritative guidance and link to their sources.

## Consequences

- The application can demonstrate Flask routes, templates, JSON loading, and filtering without implying that the observations are official.
- Users can share filter URLs, and the behavior remains straightforward to test and explain.
- Assignment 1 cannot claim real-time accuracy.
- Later assignments can replace or supplement the sample records with persistent, validated community reports and external information sources without changing the Campus Area vocabulary.
