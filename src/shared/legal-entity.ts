export const LEGAL_ENTITY: {
  operatorName: string;
  entityType: string;
  governingState: string;
  venueCounty: string | null;
} = {
  operatorName: "Cory Rankin",
  entityType: "sole proprietor",
  governingState: "North Carolina",
  venueCounty: "Wake",
};

export function venueText(): string {
  const { venueCounty, governingState } = LEGAL_ENTITY;
  return venueCounty
    ? `the state and federal courts located in ${venueCounty} County, ${governingState}`
    : `the state and federal courts located in ${governingState}`;
}
