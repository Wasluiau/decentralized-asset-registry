;; Decentralized Persistent Asset Registry with Multi-Tier Authorization Framework
;; Establishes enduring data structures with comprehensive privilege orchestration

(define-constant ERR_UNAUTHORIZED_ACCESS (err u400))
(define-constant ERR_ENTITY_NOT_FOUND (err u401))
(define-constant ERR_DUPLICATE_ENTRY (err u402))
(define-constant ERR_INVALID_PARAMETER (err u403))
(define-constant ERR_VALIDATION_FAILED (err u404))
(define-constant ERR_OPERATION_DENIED (err u405))
(define-constant ERR_IDENTITY_MISMATCH (err u406))
(define-constant ERR_CATEGORY_INVALID (err u407))
(define-constant ERR_INSUFFICIENT_RIGHTS (err u408))

(define-constant contract-administrator tx-sender)

(define-data-var global-entry-counter uint u0)

(define-map persistent-registry-entries
  { entry-id: uint }
  {
    designation: (string-ascii 64),
    custodian: principal,
    content-volume: uint,
    creation-block: uint,
    metadata-summary: (string-ascii 128),
    classification-tags: (list 10 (string-ascii 32))
  }
)

(define-map access-privilege-mappings
  { entry-id: uint, accessor: principal }
  { granted: bool }
)

(define-map time-bound-access-grants
  { entry-id: uint, accessor: principal }
  {
    granted: bool,
    valid-until-block: uint,
    access-level: uint
  }
)

(define-map activity-audit-trail
  { entry-id: uint, event-index: uint }
  {
    actor: principal,
    action-type: (string-ascii 32),
    block-number: uint,
    supplemental-info: (string-ascii 64)
  }
)

(define-map event-counter-mapping
  { entry-id: uint }
  { total-events: uint }
)

(define-map integrity-verification-log
  { entry-id: uint, verification-index: uint }
  {
    hash-value: (buff 32),
    verifier: principal,
    verification-block: uint,
    status-marker: (string-ascii 16)
  }
)

(define-map verification-index-tracker
  { entry-id: uint }
  { total-verifications: uint }
)

(define-map usage-pattern-metrics
  { entry-id: uint, accessor: principal }
  {
    total-accesses: uint,
    first-access-block: uint,
    last-access-block: uint,
    consecutive-access-count: uint,
    max-hourly-accesses: uint
  }
)

(define-map principal-restriction-status
  { user-address: principal }
  {
    is-restricted: bool,
    reason-description: (string-ascii 64),
    restriction-block: uint
  }
)

(define-map governance-vote-registry
  { vote-id: uint }
  {
    subject-entry: uint,
    proposer: principal,
    action-category: (string-ascii 32),
    target-principal: (optional principal),
    required-approvals: uint,
    current-approvals: uint,
    deadline-block: uint,
    executed: bool
  }
)

(define-map approval-signature-records
  { vote-id: uint, signer: principal }
  { has-signed: bool }
)

(define-data-var governance-proposal-counter uint u0)


(define-public (record-integrity-checkpoint 
  (entry-id uint) 
  (hash-value (buff 32)) 
  (annotation (string-ascii 64))
)
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
      (current-index (default-to u0 (get total-verifications (map-get? verification-index-tracker { entry-id: entry-id }))))
      (verification-index (+ current-index u1))
      (has-access (is-some (map-get? access-privilege-mappings { entry-id: entry-id, accessor: tx-sender })))
      (is-owner (is-eq (get custodian registry-data) tx-sender))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (or has-access is-owner) ERR_OPERATION_DENIED)
    (asserts! (is-eq (len hash-value) u32) ERR_VALIDATION_FAILED)
    (asserts! (> (len annotation) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len annotation) u65) ERR_INVALID_PARAMETER)

    (map-set integrity-verification-log
      { entry-id: entry-id, verification-index: verification-index }
      {
        hash-value: hash-value,
        verifier: tx-sender,
        verification-block: block-height,
        status-marker: "VERIFIED"
      }
    )

    (map-set verification-index-tracker
      { entry-id: entry-id }
      { total-verifications: verification-index }
    )
    (ok verification-index)
  )
)

(define-public (track-usage-event (entry-id uint) (event-category (string-ascii 32)))
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
      (current-metrics (default-to 
        { total-accesses: u0, first-access-block: block-height, last-access-block: block-height, consecutive-access-count: u0, max-hourly-accesses: u0 }
        (map-get? usage-pattern-metrics { entry-id: entry-id, accessor: tx-sender })
      ))
      (block-gap (- block-height (get last-access-block current-metrics)))
      (is-consecutive (< block-gap u10))
      (new-consecutive-count (if is-consecutive (+ (get consecutive-access-count current-metrics) u1) u1))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (> (len event-category) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len event-category) u33) ERR_INVALID_PARAMETER)

    (asserts! (not (default-to false (get is-restricted (map-get? principal-restriction-status { user-address: tx-sender })))) ERR_OPERATION_DENIED)

    (map-set usage-pattern-metrics
      { entry-id: entry-id, accessor: tx-sender }
      {
        total-accesses: (+ (get total-accesses current-metrics) u1),
        first-access-block: (get first-access-block current-metrics),
        last-access-block: block-height,
        consecutive-access-count: new-consecutive-count,
        max-hourly-accesses: (if (> new-consecutive-count (get max-hourly-accesses current-metrics)) 
                             new-consecutive-count 
                             (get max-hourly-accesses current-metrics))
      }
    )

    (if (> new-consecutive-count u50)
      (map-set principal-restriction-status
        { user-address: tx-sender }
        {
          is-restricted: true,
          reason-description: "Suspicious access pattern detected",
          restriction-block: block-height
        }
      )
      true
    )

    (ok (+ (get total-accesses current-metrics) u1))
  )
)

(define-public (log-audit-event 
  (entry-id uint) 
  (action-type (string-ascii 32)) 
  (supplemental-info (string-ascii 64))
)
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
      (current-count (default-to u0 (get total-events (map-get? event-counter-mapping { entry-id: entry-id }))))
      (event-index (+ current-count u1))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (> (len action-type) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len action-type) u33) ERR_INVALID_PARAMETER)
    (asserts! (> (len supplemental-info) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len supplemental-info) u65) ERR_INVALID_PARAMETER)

    (map-set activity-audit-trail
      { entry-id: entry-id, event-index: event-index }
      {
        actor: tx-sender,
        action-type: action-type,
        block-number: block-height,
        supplemental-info: supplemental-info
      }
    )

    (map-set event-counter-mapping
      { entry-id: entry-id }
      { total-events: event-index }
    )

    (ok event-index)
  )
)

(define-public (grant-timed-access 
  (entry-id uint) 
  (beneficiary principal) 
  (block-duration uint) 
  (access-level uint)
)
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
      (valid-until-block (+ block-height block-duration))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (is-eq (get custodian registry-data) tx-sender) ERR_OPERATION_DENIED)
    (asserts! (> block-duration u0) ERR_VALIDATION_FAILED)
    (asserts! (<= block-duration u1000000) ERR_VALIDATION_FAILED)
    (asserts! (>= access-level u1) ERR_VALIDATION_FAILED)
    (asserts! (<= access-level u5) ERR_VALIDATION_FAILED)
    (ok valid-until-block)
  )
)

(define-private (grant-single-access (beneficiary principal) (entry-id uint))
  (begin
    (map-set access-privilege-mappings
      { entry-id: entry-id, accessor: beneficiary }
      { granted: true }
    )
    entry-id
  )
)

(define-public (grant-batch-access (entry-id uint) (beneficiary-list (list 20 principal)))
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (is-eq (get custodian registry-data) tx-sender) ERR_OPERATION_DENIED)
    (asserts! (> (len beneficiary-list) u0) ERR_VALIDATION_FAILED)
    (asserts! (<= (len beneficiary-list) u20) ERR_VALIDATION_FAILED)

    (fold grant-single-access beneficiary-list entry-id)
    (ok (len beneficiary-list))
  )
)

(define-public (propose-governance-action 
  (subject-entry uint) 
  (action-category (string-ascii 32)) 
  (target-principal (optional principal)) 
  (required-approvals uint)
)
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: subject-entry }) ERR_ENTITY_NOT_FOUND))
      (vote-id (+ (var-get governance-proposal-counter) u1))
      (deadline-block (+ block-height u1440))
    )
    (asserts! (check-entry-exists subject-entry) ERR_ENTITY_NOT_FOUND)
    (asserts! (is-eq (get custodian registry-data) tx-sender) ERR_OPERATION_DENIED)
    (asserts! (> (len action-category) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len action-category) u33) ERR_INVALID_PARAMETER)
    (asserts! (>= required-approvals u2) ERR_VALIDATION_FAILED)
    (asserts! (<= required-approvals u10) ERR_VALIDATION_FAILED)

    (map-set approval-signature-records
      { vote-id: vote-id, signer: tx-sender }
      { has-signed: true }
    )

    (var-set governance-proposal-counter vote-id)
    (ok vote-id)
  )
)

(define-private (validate-classification-tag (tag (string-ascii 32)))
  (and 
    (> (len tag) u0)
    (< (len tag) u33)
  )
)

(define-private (validate-tag-collection (tags (list 10 (string-ascii 32))))
  (and
    (> (len tags) u0)
    (<= (len tags) u10)
    (is-eq (len (filter validate-classification-tag tags)) (len tags))
  )
)

(define-private (check-entry-exists (entry-id uint))
  (is-some (map-get? persistent-registry-entries { entry-id: entry-id }))
)

(define-private (verify-ownership (entry-id uint) (custodian principal))
  (match (map-get? persistent-registry-entries { entry-id: entry-id })
    registry-data (is-eq (get custodian registry-data) custodian)
    false
  )
)

(define-private (get-content-volume (entry-id uint))
  (default-to u0
    (get content-volume
      (map-get? persistent-registry-entries { entry-id: entry-id })
    )
  )
)

(define-public (register-new-entry 
  (designation (string-ascii 64))
  (content-volume uint)
  (metadata-summary (string-ascii 128))
  (classification-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (entry-id (+ (var-get global-entry-counter) u1))
    )
    (asserts! (> (len designation) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len designation) u65) ERR_INVALID_PARAMETER)
    (asserts! (> content-volume u0) ERR_VALIDATION_FAILED)
    (asserts! (< content-volume u1000000000) ERR_VALIDATION_FAILED)
    (asserts! (> (len metadata-summary) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len metadata-summary) u129) ERR_INVALID_PARAMETER)
    (asserts! (validate-tag-collection classification-tags) ERR_CATEGORY_INVALID)

    (map-insert persistent-registry-entries
      { entry-id: entry-id }
      {
        designation: designation,
        custodian: tx-sender,
        content-volume: content-volume,
        creation-block: block-height,
        metadata-summary: metadata-summary,
        classification-tags: classification-tags
      }
    )

    (map-insert access-privilege-mappings
      { entry-id: entry-id, accessor: tx-sender }
      { granted: true }
    )

    (var-set global-entry-counter entry-id)
    (ok entry-id)
  )
)

(define-public (transfer-custodianship (entry-id uint) (new-custodian principal))
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (is-eq (get custodian registry-data) tx-sender) ERR_OPERATION_DENIED)

    (map-set persistent-registry-entries
      { entry-id: entry-id }
      (merge registry-data { custodian: new-custodian })
    )
    (ok true)
  )
)

(define-public (modify-entry-attributes 
  (entry-id uint)
  (new-designation (string-ascii 64))
  (new-volume uint)
  (new-metadata (string-ascii 128))
  (new-tags (list 10 (string-ascii 32)))
)
  (let
    (
      (registry-data (unwrap! (map-get? persistent-registry-entries { entry-id: entry-id }) ERR_ENTITY_NOT_FOUND))
    )
    (asserts! (check-entry-exists entry-id) ERR_ENTITY_NOT_FOUND)
    (asserts! (is-eq (get custodian registry-data) tx-sender) ERR_OPERATION_DENIED)
    (asserts! (> (len new-designation) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len new-designation) u65) ERR_INVALID_PARAMETER)
    (asserts! (> new-volume u0) ERR_VALIDATION_FAILED)
    (asserts! (< new-volume u1000000000) ERR_VALIDATION_FAILED)
    (asserts! (> (len new-metadata) u0) ERR_INVALID_PARAMETER)
    (asserts! (< (len new-metadata) u129) ERR_INVALID_PARAMETER)
    (asserts! (validate-tag-collection new-tags) ERR_CATEGORY_INVALID)

    (map-set persistent-registry-entries
      { entry-id: entry-id }
      (merge registry-data { 
        designation: new-designation, 
        content-volume: new-volume, 
        metadata-summary: new-metadata, 
        classification-tags: new-tags 
      })
    )
    (ok true)
  )
)


