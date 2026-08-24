export function assertFixedPackagedUserDataDirectory({
  isPackaged,
  hasUserDataDirSwitch
}: {
  isPackaged: boolean
  hasUserDataDirSwitch: boolean
}): void {
  if (isPackaged && hasUserDataDirSwitch) {
    throw new Error('PACKAGED_USER_DATA_DIR_OVERRIDE_FORBIDDEN')
  }
}
